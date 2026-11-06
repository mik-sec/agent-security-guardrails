#!/usr/bin/env python3
# Copyright 2026 The Agent Security Guardrails Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Scope-aware AST, config, and feature-flag security scanner for AI agents.

Evaluates Python AST call sites, local/module variable dataflow, YAML/JSON
agent and MCP configurations, and Terraform files against all 21 controls
(`L1-01` through `L5-04`) of the Coherent 5-Layer Defense-in-Depth taxonomy.

Unlike file-wide regex scanners that skip an entire file when a guard keyword
appears once, this scanner evaluates each AST call site and function definition
within its own lexical scope and resolves module-level and function-local
variable assignments (`var_defs`) before checking security invariants.

Usage:
    python3 scanner/scan_agent_codebase.py \\
        --input <path> \\
        [--engine ast|opengrep|semgrep|hybrid] [--packs mcp,gcp-gemini|all] \\
        [--threat-model <path>] \\
        [--format markdown|json|sarif] \\
        [--output <path>] \\
        [--fail-on CRITICAL,HIGH]
"""

from __future__ import annotations

import argparse
import ast
import collections
from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
from typing import Any, Iterator, Sequence


@dataclass(frozen=True)
class ControlMetadata:
  """Static metadata for one of the 21 agent security controls."""

  control_id: str
  rule_id: str
  layer: str
  severity: str
  owasp_asi: str
  core_module: str
  title: str
  security_invariant: str
  recommended_fix: str


REPO_ROOT: Path = Path(__file__).resolve().parents[1]
SEMGREP_RULES_YAML_PATH: Path = REPO_ROOT / "rules" / "adk-core.yaml"

# Optional declarative rule packs (run through Semgrep/Opengrep with --packs). They reuse the
# core control IDs, so their findings appear in the same L1-01..L5-04 report.
OPTIONAL_RULE_PACKS_DIR: Path = REPO_ROOT / "rules"
OPTIONAL_RULE_PACKS: dict[str, str] = {
    "gcp-gemini": "gcp-gemini.yaml",
    "mcp": "mcp.yaml",
}


def resolve_rule_packs(names: Sequence[str] | str | None) -> list[Path]:
  """Maps optional pack names (or "all") to their YAML paths; raises on unknown names."""
  if not names:
    return []
  if isinstance(names, str):
    names = [names]
  wanted: list[str] = []
  for raw in names:
    for name in str(raw).split(","):
      name = name.strip().lower()
      if not name:
        continue
      if name == "all":
        wanted.extend(OPTIONAL_RULE_PACKS)
      elif name in OPTIONAL_RULE_PACKS:
        wanted.append(name)
      else:
        raise ValueError(
            f"Unknown rule pack {name!r}; expected one of {sorted(OPTIONAL_RULE_PACKS)} or 'all'."
        )
  return [OPTIONAL_RULE_PACKS_DIR / OPTIONAL_RULE_PACKS[n] for n in dict.fromkeys(wanted)]


def _parse_semgrep_rules_stdlib(yaml_text: str) -> list[dict[str, Any]]:
  """Zero-dependency fallback parser for `rules/adk-core.yaml`."""
  rules: list[dict[str, Any]] = []
  current_rule: dict[str, Any] | None = None
  in_metadata = False
  for raw_line in yaml_text.splitlines():
    stripped = raw_line.strip()
    if not stripped or stripped.startswith("#"):
      continue
    if raw_line.startswith("  - id:"):
      if current_rule is not None:
        rules.append(current_rule)
      rule_id = raw_line.split(":", 1)[1].strip().strip("'\"")
      current_rule = {"id": rule_id, "metadata": {}}
      in_metadata = False
    elif current_rule is not None:
      if raw_line.startswith("    metadata:"):
        in_metadata = True
      elif raw_line.startswith("    ") and not raw_line.startswith("      "):
        in_metadata = False
      elif in_metadata and raw_line.startswith("      ") and ":" in stripped:
        k, _, v = stripped.partition(":")
        k = k.strip()
        v = v.strip()
        if v.startswith('"') and v.endswith('"'):
          try:
            v = json.loads(v)
          except Exception:
            v = v.strip('"')
        elif v.startswith("'") and v.endswith("'"):
          v = v.strip("'")
        current_rule["metadata"][k] = v
  if current_rule is not None:
    rules.append(current_rule)
  return rules


def _load_raw_core_rules(yaml_path: Path | None = None) -> list[dict[str, Any]]:
  """Loads raw rule dictionaries from `rules/adk-core.yaml`."""
  candidates: list[Path] = []
  if yaml_path is not None:
    candidates.append(Path(yaml_path))
  candidates.extend([
      SEMGREP_RULES_YAML_PATH,
      Path.cwd() / "rules" / "adk-core.yaml",
  ])
  resolved_path = next((p for p in candidates if p.is_file()), candidates[0])
  yaml_text = resolved_path.read_text(encoding="utf-8")

  raw_rules: list[dict[str, Any]] = []
  try:
    import yaml  # type: ignore

    loaded = yaml.safe_load(yaml_text)
    if isinstance(loaded, dict) and isinstance(loaded.get("rules"), list):
      raw_rules = [r for r in loaded["rules"] if isinstance(r, dict)]
  except Exception:
    raw_rules = []

  if not raw_rules:
    raw_rules = _parse_semgrep_rules_stdlib(yaml_text)
  return raw_rules


def _load_control_catalog_from_semgrep_yaml(
    yaml_path: Path | None = None,
    raw_rules: list[dict[str, Any]] | None = None,
) -> dict[str, ControlMetadata]:
  """Loads all 21 `L1-01`..`L5-04` controls from the single-source Semgrep YAML."""
  if raw_rules is None:
    raw_rules = _load_raw_core_rules(yaml_path)

  catalog: dict[str, ControlMetadata] = {}
  for rule in raw_rules:
    rule_id = str(rule.get("id", "")).strip()
    meta = rule.get("metadata") or {}
    if not isinstance(meta, dict):
      continue
    ctrl_id = str(meta.get("control_id", "")).strip()
    if not ctrl_id or ctrl_id in catalog:
      continue
    catalog[ctrl_id] = ControlMetadata(
        control_id=ctrl_id,
        rule_id=rule_id,
        layer=str(meta.get("layer", "")),
        severity=str(meta.get("severity_tier", "HIGH")),
        owasp_asi=str(meta.get("owasp_asi", "ASI01")),
        core_module=str(meta.get("core_module") or meta.get("module") or ""),
        title=str(meta.get("title", rule_id)),
        security_invariant=str(meta.get("security_invariant", "")),
        recommended_fix=str(meta.get("recommended_fix", "")),
    )
  return catalog


_RAW_CORE_RULES: list[dict[str, Any]] = _load_raw_core_rules()
CONTROL_CATALOG: dict[str, ControlMetadata] = (
    _load_control_catalog_from_semgrep_yaml(raw_rules=_RAW_CORE_RULES)
)
RULE_ID_TO_CONTROL_ID: dict[str, str] = {
    str(rule.get("id", "")).strip(): str((rule.get("metadata") or {}).get("control_id", "")).strip()
    for rule in _RAW_CORE_RULES
    if str(rule.get("id", "")).strip()
    and isinstance(rule.get("metadata"), dict)
    and str((rule.get("metadata") or {}).get("control_id", "")).strip()
}

def _resolve_grep_binary(engine_name: str) -> str | None:
  """Resolves `semgrep` or `opengrep` from PATH, `~/.local/bin`, `~/.opengrep`, or `.venv/bin`."""
  found = shutil.which(engine_name)
  if found:
    return found
  for candidate in (
      Path.home() / ".local" / "bin" / engine_name,
      Path.home() / ".opengrep" / "cli" / "latest" / engine_name,
      REPO_ROOT / ".venv" / "bin" / engine_name,
  ):
    if candidate.is_file() and os.access(candidate, os.X_OK):
      return str(candidate)
  return None


def _run_external_grep_engine(
    input_path: Path,
    engine: str = "opengrep",
    rules_yaml: Path | Sequence[Path] | None = None,
    include_tests: bool = False,
) -> list[tuple[str, str, str, int, str, str]]:
  """Runs `semgrep` or `opengrep` against `rules/adk-core.yaml` and returns raw tuples.

  Returns tuples of `(rel_file, control_id, status, lineno, fn_or_agent, desc)`.
  """
  if engine == "hybrid":
    binary = _resolve_grep_binary("opengrep") or _resolve_grep_binary("semgrep")
  else:
    binary_name = "opengrep" if engine == "opengrep" else "semgrep"
    binary = _resolve_grep_binary(binary_name)
  if binary is None:
    return []
  binary_name = Path(binary).stem.lower()

  if rules_yaml is None:
    cfg_paths = [SEMGREP_RULES_YAML_PATH]
  elif isinstance(rules_yaml, (str, Path)):
    cfg_paths = [Path(rules_yaml)]
  else:
    cfg_paths = [Path(c) for c in rules_yaml]
  cfg_paths = [c for c in cfg_paths if c.is_file()]
  if not cfg_paths:
    return []

  cmd = [binary, "scan"]
  for cfg_path in cfg_paths:
    cmd.extend(["--config", str(cfg_path)])
  if binary_name == "semgrep":
    cmd.extend(["--metrics=off", "--disable-version-check"])
  elif binary_name == "opengrep":
    cmd.append("--taint-intrafile")
  if include_tests:
    cmd.append("--x-ignore-semgrepignore-files")
  cmd.extend(["--json", "--quiet", str(input_path)])
  sub_env = {
      **os.environ,
      "LANG": "C.UTF-8",
      "LC_ALL": "C.UTF-8",
      "PYTHONUTF8": "1",
  }
  proc = subprocess.run(cmd, capture_output=True, text=True, check=False, env=sub_env)
  if not proc.stdout:
    return []
  try:
    payload = json.loads(proc.stdout)
  except json.JSONDecodeError:
    return []

  root_dir = input_path if input_path.is_dir() else input_path.parent
  out: list[tuple[str, str, str, int, str, str]] = []
  for res in payload.get("results", []):
    if not isinstance(res, dict):
      continue
    raw_check_id = str(res.get("check_id", ""))
    short_rule_id = raw_check_id.split(".")[-1]
    extra = res.get("extra") or {}
    meta = extra.get("metadata") or {}
    ctrl_id = str(meta.get("control_id") or RULE_ID_TO_CONTROL_ID.get(short_rule_id, ""))
    if ctrl_id not in CONTROL_CATALOG:
      continue
    fpath_str = str(res.get("path", ""))
    try:
      rel_file = str(Path(fpath_str).resolve().relative_to(root_dir.resolve()))
    except ValueError:
      rel_file = Path(fpath_str).name
    start_obj = res.get("start") or {}
    lineno = int(start_obj.get("line", 1) or 1)
    msg = str(extra.get("message") or CONTROL_CATALOG[ctrl_id].title).strip()
    out.append((rel_file, ctrl_id, "ACTION_REQUIRED", lineno, f"{binary_name}:{short_rule_id}", msg))
  return out



_TEMPLATE_VAR_RE = re.compile(r"\{[a-zA-Z_][a-zA-Z0-9_.:]*\??\}")
_FENCED_CODE_BLOCK_RE = re.compile(r"```[\s\S]*?```")
_INLINE_CODE_SPAN_RE = re.compile(r"`[^`\n]+`")
_REGEX_QUANTIFIER_RE = re.compile(r"\{[0-9]+(?:,[0-9]*)?\}")
_PROMPT_CONST_NAME_RE = re.compile(
    r"(?:^|_)(?:PROMPT|INSTRUCTION|INSTRUCTIONS|SYSTEM_PROMPT)$",
    re.IGNORECASE,
)
_BQ_IDENTIFIER_NAME_RE = re.compile(
    r"(?i)(?:^[A-Z][A-Z0-9_]*$|project|dataset|table|schema|catalog|location)"
)
_PRIVILEGED_STATE_KEY_RE = re.compile(
    r"^(app:.*|user:.*|auth:.*|role:.*|user_id|permissions|is_admin|tenant_id|"
    r"_verified_user_id|sandbox_name|_code_execution_context|"
    r"_code_executor_input_files|_adk_activated_skills_.*)$"
)
_MUTATING_TOOL_PREFIX_RE = re.compile(
    r"^(delete_|remove_|destroy_|drop_|update_|modify_|grant_|revoke_|"
    r"execute_|transfer_|write_|send_|approve_|refund_|cancel_|create_|insert_)"
)
_SENSORY_OR_TOOL_PREFIX_RE = re.compile(
    r"^(get_|fetch_|query_|list_|read_|search_|lookup_|retrieve_|"
    r"delete_|remove_|destroy_|drop_|update_|modify_|grant_|revoke_|"
    r"execute_|transfer_|write_|send_|approve_|refund_|cancel_|create_|insert_)"
)
_NON_TOOL_HELPER_NAMES = frozenset({
    # Common stdlib helper names (from secure ADK agent patterns) that take
    # tool_context or identity arguments but are not LLM-callable tools.
    "bind_authenticated_user",
    "_bind_authenticated_user",
    "_extract_tool_context",
    "validate_state_delta",
    "validate_egress_url",
    "wrap_tool_output",
})
_LLM_IDENTITY_PARAMS = frozenset({
    "user_id",
    "tenant_id",
    "owner_id",
    "account_id",
    "caller_role",
    "caller_user_id",
    "current_user_id",
})
_LLM_CREDENTIAL_PARAMS = frozenset({
    "access_token",
    "refresh_token",
    "bearer_token",
    "id_token",
    "oauth_token",
    "auth_token",
    "api_key",
    "apikey",
    "client_secret",
    "password",
    "passwd",
    "secret_key",
    "private_key",
})
_MCP_CLI_SECRET_ARG_RE = re.compile(
    r"(?i)^--(?:api[-_]?key|access[-_]?token|refresh[-_]?token|bearer[-_]?token|"
    r"auth[-_]?token|oauth[-_]?token|token|password|passwd|client[-_]?secret|"
    r"secret[-_]?key)(?:=.*)?$"
)
_FACTORY_FUNC_NAME_RE = re.compile(
    r"^(?:__init__$|_?set_up$|(?:_)?(?:create|build|make|init|setup|construct|get)_)"
)
_AGENT_SUBCLASS_BASES = frozenset({
    "BaseAgent",
    "LlmAgent",
    "Agent",
    "SequentialAgent",
    "LoopAgent",
    "ParallelAgent",
})
_WORKFLOW_MUTATING_NAME_RE = re.compile(
    r"^(delete_|remove_|destroy_|drop_|update_|modify_|grant_|revoke_|"
    r"execute_|transfer_|write_|send_|approve_|refund_|cancel_|create_|insert_|"
    r"auto_approve|process_decision|.*_approve$)"
)
_OAUTH_TOKEN_STATE_KEY_RE = re.compile(
    r"(?i)(access_token|refresh_token|id_token|bearer_token|oauth_token|"
    r"auth_token|api_token|client_secret|token_cache|"
    r"(?<![a-zA-Z0-9])token(?![a-zA-Z0-9]))"
)
_OAUTH_TOKEN_STATE_VAL_RE = re.compile(
    r"(?i)(\b(?:creds|credentials|token|oauth)\w*\.to_json\s*\(|"
    r"\b(?:access_token|refresh_token|client_secret|token_cache)\b)"
)
_BENIGN_TOKEN_COUNTER_KEY_RE = re.compile(
    r"(?i)(prompt_token|output_token|token_count|token_budget|max_token|"
    r"total_token|num_token|page_token|next_page_token|csrf_token|state_token)"
)

# Test-harness paths skipped by default (Adversarial FP Critic Gate 1). Pass
# `--include-tests` to audit them. Example and benchmark directories are not
# skipped automatically; suppress them per repository in THREAT_MODEL.md Section 6.4.
_DEFAULT_EXCLUDED_TEST_DIRS = frozenset({"tests", "test", "__tests__", "fixtures"})
_TEST_FILE_NAME_RE = re.compile(r"^(?:test_.*\.py|.*_test\.py|conftest\.py)$")
_SUPPRESSION_ACTIONS = frozenset({"EXCLUDE", "VERIFY_MITIGATION"})
_CONTROL_ID_RE = re.compile(r"(?i)L[1-5]-0[1-5]")


@dataclass
class SecurityFinding:
  """Represents a single security finding with full remediation metadata."""

  finding_id: str
  control_id: str
  rule_id: str
  layer: str
  severity: str
  owasp_asi: str
  status: str  # "ACTION_REQUIRED" | "VERIFY_MITIGATION"
  file: str
  line: int
  function_or_agent: str
  title: str
  description: str
  snippet: str
  security_invariant: str
  recommended_fix: str
  core_module: str
  threat_model_ids: list[str] = field(default_factory=list)
  remediation: str = ""


def _get_call_name(node: ast.Call) -> str:
  """Returns the dotted or simple name for an `ast.Call` target."""
  func = node.func
  if isinstance(func, ast.Name):
    return func.id
  if isinstance(func, ast.Attribute):
    parts: list[str] = [func.attr]
    curr = func.value
    while isinstance(curr, ast.Attribute):
      parts.append(curr.attr)
      curr = curr.value
    if isinstance(curr, ast.Name):
      parts.append(curr.id)
    return ".".join(reversed(parts))
  return ""


def _get_kwarg(node: ast.Call, name: str) -> ast.expr | None:
  """Returns the AST expression for keyword argument `name`, or None."""
  for kw in node.keywords:
    if kw.arg == name:
      return kw.value
  return None


def _walk_without_nested_functions(node: ast.AST) -> Iterator[ast.AST]:
  """Yields descendants of `node` in document order, skipping nested function/lambda/class bodies."""
  queue: collections.deque[ast.AST] = collections.deque(ast.iter_child_nodes(node))
  while queue:
    child = queue.popleft()
    yield child
    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
      continue
    queue.extend(ast.iter_child_nodes(child))


def _extract_line_snippet(source_lines: list[str], lineno: int) -> str:
  """Returns a trimmed 1-3 line source snippet around `lineno` (1-indexed)."""
  if not source_lines or lineno < 1 or lineno > len(source_lines):
    return ""
  start = max(0, lineno - 1)
  end = min(len(source_lines), lineno + 2)
  snippet_lines = [line.rstrip() for line in source_lines[start:end]]
  return "\n".join(snippet_lines).strip()


def _has_multipart_parts0_bypass(fn_source: str) -> bool:
  """Detects callbacks that index `.parts[0]` without iterating across all `.parts`."""
  if not re.search(r"\.parts\s*\[\s*0\s*\]", fn_source):
    return False
  # Check if it also iterates over `.parts` (`for ... in ...parts`)
  if re.search(r"\bfor\s+[a-zA-Z0-9_,\s]+\s+in\s+[^\n:]*\.parts\b", fn_source):
    return False
  return True


def _has_multipart_overwrite_bypass(fn_source: str) -> bool:
  """Detects loops over `parts` that overwrite a scalar text variable (`user_text = text`)."""
  if not re.search(r"\bfor\s+[a-zA-Z0-9_,\s]+\s+in\s+[^\n:]*\bparts\b", fn_source):
    return False
  has_scalar_text_overwrite = bool(
      re.search(
          r"\b(?:user_text|model_text|message_text|final_text|extracted_text|text_content)\s*=\s*(?:text|part\.text)\b",
          fn_source,
      )
  )
  return has_scalar_text_overwrite


class _ScopeAwareSecurityVisitor(ast.NodeVisitor):
  """Scope-aware Python AST & local/module variable dataflow security visitor."""

  def __init__(
      self,
      rel_path: str,
      source_code: str,
      file_path: Path | None = None,
  ) -> None:
    self.rel_path = rel_path
    self.file_path = file_path
    self.source_code = source_code
    self.source_lines = source_code.splitlines()
    self.raw_findings: list[tuple[str, str, int, str, str]] = []
    # Stack of lexical variable bindings: var_name -> assigned ast.AST value
    self._scope_vars: list[dict[str, ast.AST]] = [{}]
    self._scope_names: list[str] = ["<module>"]
    self._class_stack: list[str] = []
    self._agent_class_stack: list[str] = []
    self._plugin_class_stack: list[str] = []
    self._tainted_sql_vars: list[set[str]] = [set()]
    self._tainted_prompt_vars: list[set[str]] = [set()]
    self._func_param_names: list[set[str]] = [set()]
    self._tainted_param_vars: list[set[str]] = [set()]
    self._func_has_query_params: list[bool] = [False]
    self._func_body_src: list[str] = [source_code]
    self._registered_tool_funcs: set[str] = set()
    self._wired_tool_func_names: set[str] = set()
    self._function_tool_wrapped_funcs: set[str] = set()
    self._confirmed_tool_funcs: set[str] = set()
    self._workflow_node_funcs: set[str] = set()
    self._callback_func_names: set[str] = set()
    self._instruction_provider_funcs: set[str] = set()
    self._has_explicit_tool_lists: bool = False
    self._file_has_sandbox_executor: bool = False
    self._non_adk_run_config_imported: bool = False
    self._subagent_var_names: set[str] = set()
    self._checked_subagent_nodes: set[int] = set()
    self._call_var_names: dict[int, str] = {}
    self._pre_vars: dict[str, ast.AST] = {}
    self._runner_guarded_agent_vars: set[str] = set()
    self._runner_guarded_agent_nodes: set[int] = set()
    self._file_has_model_armor_plugin: bool = False
    self._file_has_after_tool_guard: bool = False
    self._file_has_trigger_oidc_verifier: bool = False
    self._file_has_kms_credential_guard: bool = False
    self._formatted_const_names: set[str] = set()
    self._agent_var_names: set[str] = set()

  def _extract_workflow_edge_refs(self, expr: ast.AST | None, depth: int = 0) -> None:
    """Recursively extracts function names referenced inside `Workflow(edges=...)`."""
    if expr is None or depth > 8:
      return
    if isinstance(expr, ast.Name) and expr.id in self._pre_vars:
      self._extract_workflow_edge_refs(self._pre_vars[expr.id], depth + 1)
    for child in ast.walk(expr):
      if isinstance(child, ast.Name) and child.id not in ("START", "END", "Workflow", "Edge"):
        self._workflow_node_funcs.add(child.id)
        self._wired_tool_func_names.add(child.id)
      elif isinstance(child, ast.Attribute):
        self._workflow_node_funcs.add(child.attr)
        self._wired_tool_func_names.add(child.attr)
      elif isinstance(child, ast.Constant) and isinstance(child.value, str):
        val = child.value.strip()
        if val and val not in ("START", "END") and val.isidentifier():
          self._workflow_node_funcs.add(val)
          self._wired_tool_func_names.add(val)

  def _extract_tool_list_refs(self, tools_expr: ast.AST | None, depth: int = 0) -> None:
    """Extracts wired tool function names from `tools=[...]` expressions."""
    if tools_expr is None or depth > 6:
      return
    if isinstance(tools_expr, ast.Name) and tools_expr.id in self._pre_vars:
      self._extract_tool_list_refs(self._pre_vars[tools_expr.id], depth + 1)
      return
    if isinstance(tools_expr, (ast.List, ast.Tuple, ast.Set)):
      for elt in tools_expr.elts:
        if isinstance(elt, ast.Name):
          self._registered_tool_funcs.add(elt.id)
          self._wired_tool_func_names.add(elt.id)
          if elt.id in self._pre_vars:
            self._extract_tool_list_refs(self._pre_vars[elt.id], depth + 1)
        elif isinstance(elt, ast.Attribute):
          self._registered_tool_funcs.add(elt.attr)
          self._wired_tool_func_names.add(elt.attr)
        elif isinstance(elt, ast.Call):
          fn_node = elt.args[0] if elt.args else _get_kwarg(elt, "func")
          if isinstance(fn_node, ast.Name):
            self._registered_tool_funcs.add(fn_node.id)
            self._wired_tool_func_names.add(fn_node.id)
          elif isinstance(fn_node, ast.Attribute):
            self._registered_tool_funcs.add(fn_node.attr)
            self._wired_tool_func_names.add(fn_node.attr)

  def _extract_callback_refs(self, cb_expr: ast.AST | None) -> None:
    """Extracts callback function names from callback keyword arguments."""
    if cb_expr is None:
      return
    if isinstance(cb_expr, ast.Name):
      self._callback_func_names.add(cb_expr.id)
    elif isinstance(cb_expr, ast.Attribute):
      self._callback_func_names.add(cb_expr.attr)
    elif isinstance(cb_expr, (ast.List, ast.Tuple)):
      for elt in cb_expr.elts:
        self._extract_callback_refs(elt)

  def pre_scan(self, tree: ast.AST) -> None:
    """Collects tool registrations, workflow edges, sub-agents, and runner/app plugins."""
    for node in ast.walk(tree):
      if isinstance(node, ast.ImportFrom) and node.module:
        if "tau_bench" in node.module:
          for alias in node.names:
            if alias.name == "RunConfig" or alias.asname == "RunConfig":
              self._non_adk_run_config_imported = True
      elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        var_name = node.targets[0].id
        self._pre_vars[var_name] = node.value
        self._call_var_names[id(node.value)] = var_name
      elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
        var_name = node.target.id
        self._pre_vars[var_name] = node.value
        self._call_var_names[id(node.value)] = var_name
      elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        fn_unparsed = ast.unparse(node)
        if "request_confirmation" in fn_unparsed or "require_confirmation" in fn_unparsed:
          self._confirmed_tool_funcs.add(node.name)
        for dec in node.decorator_list:
          dec_str = ast.unparse(dec)
          if any(tok in dec_str for tok in ("tool", "node")):
            self._wired_tool_func_names.add(node.name)
      elif isinstance(node, ast.Constant) and isinstance(node.value, str):
        if node.value == "GOOGLE_CREDENTIAL_KMS_KEY":
          self._file_has_kms_credential_guard = True
      elif (
          isinstance(node, ast.Call)
          and isinstance(node.func, ast.Attribute)
          and node.func.attr in ("format", "format_map")
      ):
        recv = node.func.value
        while isinstance(recv, ast.Call) and isinstance(recv.func, ast.Attribute):
          recv = recv.func.value
        if isinstance(recv, ast.Name):
          if recv.id == "str" and node.args and isinstance(node.args[0], ast.Name):
            self._formatted_const_names.add(node.args[0].id)
          else:
            self._formatted_const_names.add(recv.id)

    for node in ast.walk(tree):
      if isinstance(node, ast.Call):
        cname = _get_call_name(node)
        sname = cname.split(".")[-1] if cname else ""
        if sname in (
            "AgentEngineSandboxCodeExecutor",
            "GkeCodeExecutor",
            "VertexAiCodeExecutor",
            "E2BEnvironment",
        ):
          self._file_has_sandbox_executor = True
        if sname in ("FunctionTool", "LongRunningFunctionTool"):
          fn_node = node.args[0] if node.args else _get_kwarg(node, "func")
          fn_id = ""
          if isinstance(fn_node, ast.Name):
            fn_id = fn_node.id
          elif isinstance(fn_node, ast.Attribute):
            fn_id = fn_node.attr
          if fn_id:
            self._registered_tool_funcs.add(fn_id)
            self._wired_tool_func_names.add(fn_id)
            self._function_tool_wrapped_funcs.add(fn_id)
            rc_kw = _get_kwarg(node, "require_confirmation")
            if rc_kw is not None:
              rc_resolved = (
                  self._pre_vars.get(rc_kw.id, rc_kw)
                  if isinstance(rc_kw, ast.Name)
                  else rc_kw
              )
              if not (
                  isinstance(rc_resolved, ast.Constant)
                  and rc_resolved.value in (False, None)
              ):
                self._confirmed_tool_funcs.add(fn_id)
        elif sname in ("LlmAgent", "Agent", "BaseAgent", "SequentialAgent", "LoopAgent", "ParallelAgent"):
          if id(node) in self._call_var_names:
            self._agent_var_names.add(self._call_var_names[id(node)])
          for cb_arg in (
              "before_model_callback",
              "after_model_callback",
              "before_agent_callback",
              "after_agent_callback",
              "before_tool_callback",
              "after_tool_callback",
          ):
            self._extract_callback_refs(_get_kwarg(node, cb_arg))
          for inst_arg_name in ("instruction", "static_instruction", "global_instruction"):
            inst_kw = _get_kwarg(node, inst_arg_name)
            if isinstance(inst_kw, ast.Name) and inst_kw.id not in self._pre_vars:
              self._instruction_provider_funcs.add(inst_kw.id)
              self._callback_func_names.add(inst_kw.id)
            elif isinstance(inst_kw, ast.Attribute):
              self._instruction_provider_funcs.add(inst_kw.attr)
              self._callback_func_names.add(inst_kw.attr)
          ce_kw = _get_kwarg(node, "code_executor")
          if ce_kw is not None:
            ce_resolved = (
                self._pre_vars.get(ce_kw.id, ce_kw)
                if isinstance(ce_kw, ast.Name)
                else ce_kw
            )
            ce_str = ast.unparse(ce_resolved)
            if any(
                sb in ce_str
                for sb in (
                    "AgentEngineSandboxCodeExecutor",
                    "GkeCodeExecutor",
                    "VertexAiCodeExecutor",
                    "E2BEnvironment",
                )
            ):
              self._file_has_sandbox_executor = True
          tools_kw = _get_kwarg(node, "tools")
          if tools_kw is not None:
            self._has_explicit_tool_lists = True
            self._extract_tool_list_refs(tools_kw)
          sub_kw = _get_kwarg(node, "sub_agents")
          if isinstance(sub_kw, (ast.List, ast.Tuple)):
            for elt in sub_kw.elts:
              if isinstance(elt, ast.Name):
                self._subagent_var_names.add(elt.id)
        elif sname == "Workflow":
          self._has_explicit_tool_lists = True
          edges_kw = _get_kwarg(node, "edges")
          if edges_kw is not None:
            self._extract_workflow_edge_refs(edges_kw)
          for pos_arg in node.args:
            self._extract_workflow_edge_refs(pos_arg)
        elif sname in ("Runner", "InMemoryRunner", "App"):
          p_kw = _get_kwarg(node, "plugins")
          if isinstance(p_kw, ast.Name) and p_kw.id in self._pre_vars:
            p_kw = self._pre_vars[p_kw.id]
          has_p = (
              p_kw is not None
              and not (isinstance(p_kw, (ast.List, ast.Tuple)) and not p_kw.elts)
              and not (isinstance(p_kw, ast.Constant) and p_kw.value is None)
          )
          if has_p:
            ag_kw = _get_kwarg(node, "agent") or _get_kwarg(node, "root_agent")
            if isinstance(ag_kw, ast.Name):
              self._runner_guarded_agent_vars.add(ag_kw.id)
            elif isinstance(ag_kw, ast.Call):
              self._runner_guarded_agent_nodes.add(id(ag_kw))
        elif sname == "ModelArmorPlugin":
          self._file_has_model_armor_plugin = True
        elif sname == "wrap_tool_output":
          self._file_has_after_tool_guard = True
        elif sname == "GoogleOidcVerifier":
          self._file_has_trigger_oidc_verifier = True

  def _resolve(self, expr: ast.expr | None, depth: int = 0) -> ast.expr | None:
    """Resolves an `ast.Name` or `ast.Subscript` variable reference through lexical scopes."""
    if expr is None or depth > 6:
      return expr
    if isinstance(expr, ast.Name):
      for scope in reversed(self._scope_vars):
        if expr.id in scope:
          resolved = scope[expr.id]
          if resolved is not expr and isinstance(resolved, ast.expr):
            return self._resolve(resolved, depth + 1)
      if expr.id in self._pre_vars:
        resolved = self._pre_vars[expr.id]
        if resolved is not expr and isinstance(resolved, ast.expr):
          return self._resolve(resolved, depth + 1)
    elif isinstance(expr, ast.Subscript):
      slice_node = self._resolve(expr.slice, depth + 1)
      if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, str):
        key_str = slice_node.value
        target = self._resolve(expr.value, depth + 1)
        if isinstance(target, ast.Dict):
          for k, v in zip(target.keys, target.values):
            if isinstance(k, ast.Constant) and k.value == key_str:
              return self._resolve(v, depth + 1)
        elif isinstance(target, ast.Call):
          sname = _get_call_name(target).split(".")[-1]
          if sname in (
              "create_isolated_subagent_spec",
              "project_subagent_context",
              "get_isolated_subagent_kwargs",
          ):
            if key_str == "name" and sname == "create_isolated_subagent_spec":
              name_arg = (
                  target.args[0]
                  if target.args
                  else (_get_kwarg(target, "subagent_name") or _get_kwarg(target, "name"))
              )
              if name_arg is not None:
                return self._resolve(name_arg, depth + 1)
            elif key_str == "include_contents":
              inc_arg = _get_kwarg(target, "include_contents")
              if inc_arg is not None:
                return self._resolve(inc_arg, depth + 1)
              return ast.Constant(value="none")
            elif key_str in ("disallow_transfer_to_peers", "disallow_transfer_to_parent"):
              return ast.Constant(value=True)
    return expr

  def _is_const_concat_tree(
      self,
      node: ast.expr,
      visited: set[int] | None = None,
      depth: int = 0,
      memo: dict[int, bool] | None = None,
  ) -> bool:
    """Returns True if `node` is a constant or an `ast.Add` / `ast.Mult` tree of constants."""
    if memo is None:
      memo = {}
    orig_id = id(node)
    if orig_id in memo:
      return memo[orig_id]
    if depth > 24:
      memo[orig_id] = False
      return False
    if visited is None:
      visited = set()
    if orig_id in visited:
      return False
    visited = visited | {orig_id}
    if isinstance(node, ast.Name):
      for tset in reversed(self._tainted_sql_vars):
        if node.id in tset:
          memo[orig_id] = False
          return False
      resolved = self._resolve(node)
      if resolved is None or isinstance(resolved, ast.Name) or id(resolved) in visited:
        memo[orig_id] = False
        return False
      visited = visited | {id(resolved)}
      node = resolved
    if isinstance(node, ast.Constant):
      memo[orig_id] = True
      return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mult)):
      res = (
          self._is_const_concat_tree(node.left, visited, depth + 1, memo)
          and self._is_const_concat_tree(node.right, visited, depth + 1, memo)
      )
      memo[orig_id] = res
      return res
    memo[orig_id] = False
    return False

  def _is_tainted_sql(self, expr: ast.expr | None) -> bool:
    """Returns True if `expr` is dynamically formatted SQL or a tainted var."""
    if expr is None:
      return False
    if isinstance(expr, ast.Name):
      for tset in reversed(self._tainted_sql_vars):
        if expr.id in tset:
          return True
      expr = self._resolve(expr)
      if expr is None or isinstance(expr, ast.Name):
        return False
    if isinstance(expr, ast.JoinedStr):
      return True
    if isinstance(expr, ast.Call):
      if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
        return True
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Mod, ast.Add)):
      if isinstance(expr.op, ast.Add) and self._is_const_concat_tree(expr):
        return False
      return True
    return False

  def _is_safe_sql_interp_expr(self, expr: ast.expr, depth: int = 0) -> bool:
    """Returns True if `expr` inside a SQL f-string is a constant/attribute table/dataset/project identifier."""
    if depth > 6:
      return False
    for child in ast.walk(expr):
      if isinstance(child, ast.Name) and (
          child.id in self._func_param_names[-1]
          or child.id in self._tainted_param_vars[-1]
      ):
        return False
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
      return True
    if isinstance(expr, ast.Name):
      resolved = self._resolve(expr)
      if resolved is not None and resolved is not expr:
        return self._is_safe_sql_interp_expr(resolved, depth + 1)
      return bool(_BQ_IDENTIFIER_NAME_RE.search(expr.id))
    if isinstance(expr, ast.Attribute):
      return bool(_BQ_IDENTIFIER_NAME_RE.search(expr.attr))
    if isinstance(expr, ast.JoinedStr):
      return all(
          self._is_safe_sql_interp_expr(fv.value, depth + 1)
          for fv in expr.values
          if isinstance(fv, ast.FormattedValue)
      )
    return False

  def _is_dynamic_or_brace_prompt(self, expr: ast.expr | None) -> tuple[bool, str]:
    """Checks whether an instruction expression uses f-string, format, %, or {var}."""
    if expr is None:
      return False, ""
    if isinstance(expr, ast.Name):
      for tset in reversed(self._tainted_prompt_vars):
        if expr.id in tset:
          resolved_check = self._resolve(expr)
          if isinstance(resolved_check, ast.JoinedStr):
            return True, "f-string interpolation"
          if (
              isinstance(resolved_check, ast.Call)
              and isinstance(resolved_check.func, ast.Attribute)
              and resolved_check.func.attr == "format"
          ):
            return True, ".format() string interpolation"
          return True, f"dynamically formatted prompt variable '{expr.id}'"
    resolved = self._resolve(expr)
    if resolved is None:
      return False, ""
    if isinstance(resolved, ast.JoinedStr):
      return True, "f-string interpolation"
    if isinstance(resolved, ast.Call):
      cname = _get_call_name(resolved)
      sname = cname.split(".")[-1] if cname else ""
      if isinstance(resolved.func, ast.Attribute) and resolved.func.attr == "format":
        return True, ".format() string interpolation"
    if isinstance(resolved, ast.BinOp) and isinstance(resolved.op, (ast.Mod, ast.Add)):
      if isinstance(resolved.op, ast.Mod):
        return True, "'%' string interpolation"
      if not self._is_const_concat_tree(resolved):
        return True, "string concatenation with dynamic variable"
    if isinstance(resolved, ast.Constant) and isinstance(resolved.value, str):
      sanitized_str = resolved.value.replace("{{", "").replace("}}", "")
      sanitized_str = _FENCED_CODE_BLOCK_RE.sub("", sanitized_str)
      sanitized_str = _INLINE_CODE_SPAN_RE.sub("", sanitized_str)
      sanitized_str = _REGEX_QUANTIFIER_RE.sub("", sanitized_str)
      match = _TEMPLATE_VAR_RE.search(sanitized_str)
      if match:
        return True, f"unescaped template placeholder '{match.group(0)}'"
    return False, ""

  def _eval_bool(self, expr: ast.expr | None) -> bool | None:
    """Evaluates a boolean constant or variable resolving to a boolean."""
    resolved = self._resolve(expr)
    if isinstance(resolved, ast.Constant) and isinstance(resolved.value, bool):
      return resolved.value
    return None

  def _eval_str(self, expr: ast.expr | None) -> str | None:
    """Evaluates a string constant or variable resolving to a string."""
    resolved = self._resolve(expr)
    if isinstance(resolved, ast.Constant) and isinstance(resolved.value, str):
      return resolved.value
    return None

  def _extract_leading_arg_str(self, expr: ast.expr | None, depth: int = 0) -> str | None:
    """Extracts a constant string or leading string prefix from f-strings, `.format()`, or `+`."""
    if expr is None or depth > 6:
      return None
    direct = self._eval_str(expr)
    if direct is not None:
      return direct
    resolved = self._resolve(expr)
    if isinstance(resolved, ast.JoinedStr) and resolved.values:
      return self._eval_str(resolved.values[0])
    if isinstance(resolved, ast.BinOp) and isinstance(resolved.op, ast.Add):
      left_prefix = self._extract_leading_arg_str(resolved.left, depth + 1)
      if left_prefix is None:
        return None
      right_direct = self._eval_str(resolved.right)
      if right_direct is not None:
        return left_prefix + right_direct
      right_prefix = self._extract_leading_arg_str(resolved.right, depth + 1)
      if right_prefix is not None and isinstance(resolved.left, ast.Constant):
        return left_prefix + right_prefix
      return left_prefix
    if (
        isinstance(resolved, ast.Call)
        and isinstance(resolved.func, ast.Attribute)
        and resolved.func.attr in ("format", "format_map")
    ):
      recv_str = self._eval_str(resolved.func.value)
      if recv_str is not None:
        return recv_str.split("{", 1)[0]
    return None

  def _eval_int(self, expr: ast.expr | None) -> int | None:
    """Evaluates an integer constant or variable resolving to an integer."""
    resolved = self._resolve(expr)
    if isinstance(resolved, ast.Constant) and isinstance(resolved.value, int) and not isinstance(resolved.value, bool):
      return resolved.value
    if (
        isinstance(resolved, ast.UnaryOp)
        and isinstance(resolved.op, ast.USub)
        and isinstance(resolved.operand, ast.Constant)
        and isinstance(resolved.operand.value, int)
    ):
      return -resolved.operand.value
    return None

  def _record(
      self,
      control_id: str,
      node: ast.AST,
      description: str,
      context_name: str | None = None,
      status: str = "ACTION_REQUIRED",
  ) -> None:
    lineno = getattr(node, "lineno", 1)
    fn_or_agent = context_name or self._scope_names[-1]
    self.raw_findings.append((control_id, status, lineno, fn_or_agent, description))

  def _is_plaintext_token_state_entry(
      self,
      key_str: str,
      val_node: ast.expr | None,
      val_unparsed: str,
  ) -> bool:
    """Returns True if `key_str` or `val_node` caches plaintext OAuth tokens/secrets in state."""
    if _BENIGN_TOKEN_COUNTER_KEY_RE.search(key_str):
      return False
    resolved_val = self._resolve(val_node) if val_node is not None else None
    if isinstance(resolved_val, ast.Constant) and isinstance(
        resolved_val.value, (int, float, bool)
    ):
      return False
    if _OAUTH_TOKEN_STATE_KEY_RE.search(key_str):
      return True
    if _OAUTH_TOKEN_STATE_VAL_RE.search(val_unparsed):
      return True
    if resolved_val is not None and _OAUTH_TOKEN_STATE_VAL_RE.search(
        ast.unparse(resolved_val)
    ):
      return True
    return False

  def _has_nonempty_plugins(self, call_node: ast.Call) -> bool:
    """Returns True if `call_node` passes a non-empty `plugins` keyword argument."""
    plugins_kw = self._resolve(_get_kwarg(call_node, "plugins"))
    return (
        plugins_kw is not None
        and not (
            isinstance(plugins_kw, (ast.List, ast.Tuple)) and not plugins_kw.elts
        )
        and not (
            isinstance(plugins_kw, ast.Constant) and plugins_kw.value is None
        )
    )

  def _agent_expr_has_guardrail(self, agent_expr: ast.expr | None) -> bool:
    """Returns True if `agent_expr` resolves to an agent call with before_model/agent_callback."""
    resolved = self._resolve(agent_expr)
    if isinstance(resolved, ast.Call):
      for cb_name in ("before_model_callback", "before_agent_callback"):
        cb_kw = self._resolve(_get_kwarg(resolved, cb_name))
        if cb_kw is not None and not (
            isinstance(cb_kw, ast.Constant) and cb_kw.value is None
        ):
          return True
    return False

  def _are_skills_prompt_only(self, call_node: ast.Call | None = None) -> bool:
    """Returns True if `SkillToolset` is prompt-only (no `scripts/`, no `RunSkillScriptTool`, no `adk_inject_state: true`)."""
    if "RunSkillScriptTool" in self.source_code:
      return False
    if call_node is not None and (
        _get_kwarg(call_node, "code_executor") is not None
        or _get_kwarg(call_node, "environment") is not None
    ):
      return False
    if self.file_path is None or not self.file_path.is_file():
      return call_node is not None and _get_kwarg(call_node, "skills") is not None
    parent_dir = self.file_path.parent
    skill_mds = list(parent_dir.rglob("SKILL.md"))
    for p in parent_dir.rglob("*"):
      if p.is_dir() and p.name == "scripts" and any(p.iterdir()):
        return False
    for smd in skill_mds:
      try:
        smd_text = smd.read_text(encoding="utf-8")
      except (OSError, UnicodeDecodeError):
        continue
      if re.search(r"\badk_inject_state\s*:\s*(true|yes|1)\b", smd_text, re.IGNORECASE):
        return False
    return True

  def visit_ClassDef(self, node: ast.ClassDef) -> None:
    base_snames: set[str] = set()
    for b in node.bases:
      if isinstance(b, ast.Name):
        base_snames.add(b.id)
      elif isinstance(b, ast.Attribute):
        base_snames.add(b.attr)
      elif isinstance(b, ast.Subscript):
        if isinstance(b.value, ast.Name):
          base_snames.add(b.value.id)
        elif isinstance(b.value, ast.Attribute):
          base_snames.add(b.value.attr)

    is_agent_cls = bool(base_snames & _AGENT_SUBCLASS_BASES)
    is_plugin_cls = "BasePlugin" in base_snames
    self._class_stack.append(node.name)
    if is_agent_cls:
      self._agent_class_stack.append(node.name)
    if is_plugin_cls:
      self._plugin_class_stack.append(node.name)
    self._scope_names.append(node.name)
    self._scope_vars.append({})
    self._tainted_sql_vars.append(set())
    self._tainted_prompt_vars.append(set())
    self._func_param_names.append(set())
    self._tainted_param_vars.append(set())
    self._func_has_query_params.append(False)
    self._func_body_src.append(ast.unparse(node))
    self.generic_visit(node)
    self._func_body_src.pop()
    self._func_has_query_params.pop()
    self._tainted_param_vars.pop()
    self._func_param_names.pop()
    self._tainted_prompt_vars.pop()
    self._tainted_sql_vars.pop()
    self._scope_vars.pop()
    self._scope_names.pop()
    if is_plugin_cls:
      self._plugin_class_stack.pop()
    if is_agent_cls:
      self._agent_class_stack.pop()
    self._class_stack.pop()

  def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
    self._visit_function(node)

  def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
    self._visit_function(node)

  def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
    all_args = (
        list(node.args.posonlyargs)
        + list(node.args.args)
        + list(node.args.kwonlyargs)
    )
    param_set = {
        a.arg
        for a in all_args
        if a.arg
        not in (
            "self",
            "cls",
            "tool_context",
            "ctx",
            "callback_context",
            "readonly_context",
        )
    }
    fn_src = ast.unparse(node)
    has_qparams = any(
        qp in fn_src
        for qp in (
            "ScalarQueryParameter",
            "ArrayQueryParameter",
            "StructQueryParameter",
            "query_parameters",
        )
    )

    self._check_base_agent_impl_security(node)
    self._check_instruction_provider_security(node)
    self._check_callback_multipart_security(node)
    self._check_workflow_node_security(node)
    self._check_function_security(node)
    self._scope_names.append(node.name)
    self._scope_vars.append({})
    self._tainted_sql_vars.append(set(self._tainted_sql_vars[-1]))
    self._tainted_prompt_vars.append(set(self._tainted_prompt_vars[-1]))
    self._func_param_names.append(param_set)
    self._tainted_param_vars.append(set(param_set))
    self._func_has_query_params.append(has_qparams)
    self._func_body_src.append(fn_src)
    self.generic_visit(node)
    self._func_body_src.pop()
    self._func_has_query_params.pop()
    self._tainted_param_vars.pop()
    self._func_param_names.pop()
    self._tainted_prompt_vars.pop()
    self._tainted_sql_vars.pop()
    self._scope_vars.pop()
    self._scope_names.pop()

  def _has_callback_or_readonly_context_only(
      self, node: ast.FunctionDef | ast.AsyncFunctionDef
  ) -> tuple[bool, bool]:
    """Returns `(is_callback_or_readonly_only, has_explicit_tool_context)`."""
    all_args = (
        list(node.args.posonlyargs)
        + list(node.args.args)
        + list(node.args.kwonlyargs)
    )
    arg_names = [a.arg for a in all_args if a.arg not in ("self", "cls")]
    has_cb_or_ro = any(
        a in ("callback_context", "readonly_context") for a in arg_names
    ) or any(
        a.annotation is not None
        and re.search(
            r"\b(CallbackContext|ReadonlyContext)\b", ast.unparse(a.annotation)
        )
        for a in all_args
    )
    has_tool_ctx = any(a == "tool_context" for a in arg_names) or any(
        a.annotation is not None
        and re.search(r"\bToolContext\b", ast.unparse(a.annotation))
        for a in all_args
    )
    if (
        node.name in self._callback_func_names
        and node.name not in self._wired_tool_func_names
    ):
      has_cb_or_ro = True
    return (has_cb_or_ro and not has_tool_ctx), has_tool_ctx

  def _check_instruction_provider_security(
      self, node: ast.FunctionDef | ast.AsyncFunctionDef
  ) -> None:
    """Checks `InstructionProvider` / `ReadonlyContext` functions formatting `.state` into prompts (L1-01)."""
    if self._plugin_class_stack or node.name in (
        "before_agent_callback",
        "after_agent_callback",
        "before_model_callback",
        "after_model_callback",
        "before_tool_callback",
        "after_tool_callback",
        "on_tool_error_callback",
        "on_user_message_callback",
        "on_event_callback",
        "before_run_callback",
        "after_run_callback",
    ):
      return
    all_args = (
        list(node.args.posonlyargs)
        + list(node.args.args)
        + list(node.args.kwonlyargs)
    )
    arg_names = [a.arg for a in all_args if a.arg not in ("self", "cls")]
    has_ro_or_cb = (
        any(a in ("readonly_context", "callback_context") for a in arg_names)
        or any(
            a.annotation is not None
            and re.search(
                r"\b(ReadonlyContext|CallbackContext)\b",
                ast.unparse(a.annotation),
            )
            for a in all_args
        )
        or node.name in self._instruction_provider_funcs
    )
    if not has_ro_or_cb:
      return
    fn_src = ast.unparse(node)
    if ".state" not in fn_src:
      return
    if "<untrusted_" in fn_src:
      return
    has_formatted_return = False
    for child in ast.walk(node):
      if isinstance(child, ast.JoinedStr):
        has_formatted_return = True
        break
      if (
          isinstance(child, ast.Call)
          and isinstance(child.func, ast.Attribute)
          and child.func.attr == "format"
      ):
        has_formatted_return = True
        break
    if has_formatted_return:
      self._record(
          "L1-01",
          node,
          (
              f"InstructionProvider / context function '{node.name}' formats "
              "untrusted `.state` into an f-string or `.format()` prompt without "
              "fencing the values in `<untrusted_...>` XML tags (L1-01)."
          ),
          context_name=node.name,
      )

  def _check_callback_multipart_security(
      self, node: ast.FunctionDef | ast.AsyncFunctionDef
  ) -> None:
    """Checks callback functions for `.parts[0]` or loop-overwrite multi-part bypass (`L1-03`)."""
    all_args = (
        list(node.args.posonlyargs)
        + list(node.args.args)
        + list(node.args.kwonlyargs)
    )
    arg_names = [a.arg for a in all_args if a.arg not in ("self", "cls")]
    ann_str = " ".join(
        ast.unparse(a.annotation) for a in all_args if a.annotation is not None
    )
    is_cb = (
        node.name
        in (
            "on_user_message_callback",
            "before_model_callback",
            "after_agent_callback",
            "before_agent_callback",
        )
        or "callback" in node.name.lower()
        or node.name in self._callback_func_names
        or any(a in ("callback_context", "llm_request") for a in arg_names)
        or any(tok in ann_str for tok in ("CallbackContext", "LlmRequest"))
    )
    if not is_cb:
      return
    fn_src = ast.unparse(node)
    if _has_multipart_parts0_bypass(fn_src) or _has_multipart_overwrite_bypass(
        fn_src
    ):
      self._record(
          "L1-03",
          node,
          (
              f"Callback function '{node.name}' inspects only `.parts[0]` or "
              "overwrites its verdict across parts without short-circuiting, "
              "allowing multi-part Content(parts=[...]) prompt-injection bypass (L1-03)."
          ),
          context_name=node.name,
      )

  def _check_base_agent_impl_security(
      self, node: ast.FunctionDef | ast.AsyncFunctionDef
  ) -> None:
    """Checks sub-agent delegation and `Runner.run_async(state_delta=...)` calls for L4-01 leaks.

    Flags (a) sub-agent `run_async`/`run_live` delegation inside `_run_async_impl` /
    agent classes or functions that handle `state_delta`, and (b) `Runner` invocations
    that pass a non-empty `state_delta` without `validate_state_delta()`. A top-level
    `runner.run_async(...)` without `state_delta` is not a sub-agent delegation and is
    not flagged. Nested function bodies are skipped here because `_visit_function`
    visits them separately (prevents duplicate findings on the same line).
    """
    is_agent_run_method = (
        node.name in ("_run_async_impl", "_run_live_impl")
        or bool(self._agent_class_stack)
    )
    fn_src = ast.unparse(node)
    has_child_delta_filter = "validate_state_delta" in fn_src
    if has_child_delta_filter:
      return

    for child in _walk_without_nested_functions(node):
      if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
        if child.func.attr in ("run_async", "run_live"):
          recv_str = ast.unparse(child.func.value)
          if "runner" in recv_str.lower():
            sd_kw = _get_kwarg(child, "state_delta")
            should_flag = sd_kw is not None and not (
                (isinstance(sd_kw, ast.Constant) and sd_kw.value is None)
                or (isinstance(sd_kw, ast.Dict) and not sd_kw.keys)
            )
          else:
            should_flag = is_agent_run_method or "state_delta" in fn_src
          if should_flag:
            ctx_label = (
                f"{self._agent_class_stack[-1]}.{node.name}"
                if self._agent_class_stack
                else node.name
            )
            self._record(
                "L4-01",
                child,
                (
                    f"Sub-agent invocation '{recv_str}.{child.func.attr}(...)' in "
                    f"'{ctx_label}' yields or applies child state_delta without "
                    "key validation such as `validate_state_delta()` (L4-01)."
                ),
                context_name=ctx_label,
            )

  def _check_workflow_node_security(
      self, node: ast.FunctionDef | ast.AsyncFunctionDef
  ) -> None:
    """Checks ADK 2.0 `Workflow(edges=...)` and `@node` functions for L3-01 HITL confirmation."""
    if node.name in _NON_TOOL_HELPER_NAMES or self._class_stack:
      return
    if node.name in (
        "_run_async_impl",
        "_run_live_impl",
        "before_agent_callback",
        "after_agent_callback",
        "before_model_callback",
        "after_model_callback",
        "before_tool_callback",
        "after_tool_callback",
    ):
      return

    is_cb_only, has_explicit_tool_ctx = self._has_callback_or_readonly_context_only(node)
    if is_cb_only:
      return

    all_args = (
        list(node.args.posonlyargs)
        + list(node.args.args)
        + list(node.args.kwonlyargs)
    )
    has_node_decorator = False
    has_decorator_confirmation = False
    for dec in node.decorator_list:
      dec_str = ast.unparse(dec)
      if isinstance(dec, ast.Name) and dec.id == "node":
        has_node_decorator = True
      elif isinstance(dec, ast.Attribute) and dec.attr == "node":
        has_node_decorator = True
      elif isinstance(dec, ast.Call):
        dname = _get_call_name(dec).split(".")[-1]
        if dname == "node":
          has_node_decorator = True
        rc_kw = _get_kwarg(dec, "require_confirmation")
        if rc_kw is not None and self._eval_bool(rc_kw) is True:
          has_decorator_confirmation = True

    has_adk_context_annotation = False
    for a in all_args:
      if a.annotation is not None:
        ann_str = ast.unparse(a.annotation)
        if re.search(r"\b(Context|InvocationContext)\b", ann_str):
          has_adk_context_annotation = True
          break

    if (
        self._has_explicit_tool_lists
        and node.name not in self._wired_tool_func_names
        and not has_node_decorator
        and not has_explicit_tool_ctx
    ):
      return

    is_workflow_node = (
        node.name in self._workflow_node_funcs
        or has_node_decorator
        or has_adk_context_annotation
    )
    if not is_workflow_node:
      return

    self._workflow_node_funcs.add(node.name)
    fn_src = ast.unparse(node)
    if (
        has_decorator_confirmation
        or node.name in self._confirmed_tool_funcs
        or "require_confirmation" in fn_src
        or "request_confirmation" in fn_src
    ):
      return

    has_mutating_name = bool(_WORKFLOW_MUTATING_NAME_RE.match(node.name))
    has_mutating_external_call = False
    for child in ast.walk(node):
      if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
        m_attr = child.func.attr
        if m_attr in ("set", "delete", "insert", "post", "put", "patch"):
          recv_unp = ast.unparse(child.func.value)
          if recv_unp not in ("os.environ", "environ", "state") and not recv_unp.endswith(".state"):
            has_mutating_external_call = True
            break

    if has_mutating_name or has_mutating_external_call:
      # Avoid duplicate L3-01 if also registered in FunctionTool without confirmation
      if node.name not in self._function_tool_wrapped_funcs:
        self._record(
            "L3-01",
            node,
            (
                f"Workflow node function '{node.name}' performs state-mutating "
                "operations without `require_confirmation=True` or `tool_context.request_confirmation()` "
                "HITL confirmation gate (L3-01)."
            ),
            context_name=node.name,
        )

  def _check_function_security(
      self, node: ast.FunctionDef | ast.AsyncFunctionDef
  ) -> None:
    """Checks tool function definitions for L2-02, L3-01, L3-02, and L4-04."""
    if node.name in _NON_TOOL_HELPER_NAMES or self._class_stack:
      return

    is_cb_only, has_explicit_tool_ctx = self._has_callback_or_readonly_context_only(node)
    if is_cb_only:
      return

    all_args = (
        list(node.args.posonlyargs)
        + list(node.args.args)
        + list(node.args.kwonlyargs)
    )
    arg_names = [a.arg for a in all_args if a.arg not in ("self", "cls")]
    dec_strings = [ast.unparse(d) for d in node.decorator_list]

    is_decorated_tool = any(
        "tool" in d
        for d in dec_strings
    )
    has_tool_context = has_explicit_tool_ctx or any(a == "ctx" for a in arg_names)
    is_registered_tool = node.name in self._registered_tool_funcs
    is_http_route = any(
        isinstance(d, ast.Call)
        and isinstance(d.func, ast.Attribute)
        and d.func.attr
        in {
            "get",
            "post",
            "put",
            "delete",
            "patch",
            "options",
            "head",
            "trace",
            "route",
            "api_route",
            "websocket",
        }
        for d in node.decorator_list
    )
    if is_http_route and not (is_registered_tool or has_explicit_tool_ctx):
      return
    looks_like_tool = (
        bool(_SENSORY_OR_TOOL_PREFIX_RE.match(node.name))
        and not node.name.startswith("_")
        and (
            not self._has_explicit_tool_lists
            or node.name in self._wired_tool_func_names
            or is_decorated_tool
            or has_explicit_tool_ctx
        )
    )

    if not (is_decorated_tool or has_tool_context or is_registered_tool or looks_like_tool):
      return

    # L3-01: State-mutating tool wired directly in tools=[...] without FunctionTool confirmation or request_confirmation()
    if (
        node.name in self._wired_tool_func_names
        and node.name not in self._function_tool_wrapped_funcs
        and node.name not in self._workflow_node_funcs
        and node.name not in self._confirmed_tool_funcs
        and _MUTATING_TOOL_PREFIX_RE.match(node.name)
        and not any("require_confirmation" in d for d in dec_strings)
    ):
      self._record(
          "L3-01",
          node,
          (
              f"State-mutating tool function '{node.name}' is registered in "
              "`tools=[...]` without `FunctionTool(..., require_confirmation=True)` "
              "or `tool_context.request_confirmation()` (L3-01)."
          ),
          context_name=node.name,
      )

    # L2-01: Tool exposing raw credential parameters (access_token, api_key, password, etc.) to LLM population
    if is_registered_tool or is_decorated_tool or has_explicit_tool_ctx:
      exposed_cred_params = [a for a in arg_names if a in _LLM_CREDENTIAL_PARAMS]
      if exposed_cred_params:
        self._record(
            "L2-01",
            node,
            (
                f"Tool function '{node.name}' exposes credential parameter(s) "
                f"{exposed_cred_params} to LLM population, leaking secrets into "
                "prompts and traces; retrieve scoped credentials server-side via "
                "tool_context (L2-01)."
            ),
            context_name=node.name,
        )

    # L3-01: Registered ADK tool accepting unconstrained **kwargs
    if (
        (is_registered_tool or has_explicit_tool_ctx)
        and not node.name.startswith("_")
        and node.args.kwarg is not None
    ):
      self._record(
          "L3-01",
          node,
          (
              f"Registered ADK tool function '{node.name}' accepts unconstrained "
              f"'**{node.args.kwarg.arg}' keyword arguments, bypassing strict "
              "tool schema validation (L3-01)."
          ),
          context_name=node.name,
      )

    # L2-02: Tool exposing LLM-controlled user_id / tenant_id / owner_id / account_id / caller_role
    exposed_id_params = [a for a in arg_names if a in _LLM_IDENTITY_PARAMS]
    if exposed_id_params:
      self._record(
          "L2-02",
          node,
          (
              f"Tool function '{node.name}' exposes identity parameter(s) "
              f"{exposed_id_params} to LLM population (BOLA / IDOR). Read "
              "authenticated caller identity exclusively from tool_context.user_id "
              "via bind_authenticated_user(tool_context)."
          ),
          context_name=node.name,
      )


  def _track_assignment(
      self, target: ast.expr, value: ast.expr, stmt_node: ast.AST
  ) -> None:
    """Tracks variable bindings, SQL/prompt/param taint, and module-level prompt constants."""
    val_unparsed = ast.unparse(value)
    is_sanitized_path = any(
        g in val_unparsed
        for g in ("os.path.basename",)
    )
    has_tainted_param = not is_sanitized_path and any(
        isinstance(n, ast.Name) and n.id in self._tainted_param_vars[-1]
        for n in ast.walk(value)
    )
    if has_tainted_param:
      for tnode in ast.walk(target):
        if isinstance(tnode, ast.Name):
          self._tainted_param_vars[-1].add(tnode.id)

    if isinstance(target, ast.Name):
      self._scope_vars[-1][target.id] = value
      if self._is_tainted_sql(value):
        self._tainted_sql_vars[-1].add(target.id)
      is_bad_p, p_reason = self._is_dynamic_or_brace_prompt(value)
      if is_bad_p:
        self._tainted_prompt_vars[-1].add(target.id)
      # Part B.2: Module-level prompt constant (`*_PROMPT`, `*_INSTRUCTION`) containing `{var}` / `{var?}`
      if (
          self._scope_names[-1] == "<module>"
          and _PROMPT_CONST_NAME_RE.search(target.id)
          and is_bad_p
          and "unescaped template placeholder" in p_reason
          and target.id not in self._formatted_const_names
          and (
              any(tok in self.source_code for tok in ("google.adk", "LlmAgent", "Agent("))
              or bool(
                  re.search(
                      r"\{(?:(?:user|app|temp):|artifact\.|[a-zA-Z_][a-zA-Z0-9_.:]*\?)",
                      val_unparsed,
                  )
              )
          )
      ):
        self._record(
            "L1-01",
            stmt_node,
            (
                f"Module-level prompt constant '{target.id}' contains {p_reason} "
                "that ADK will interpolate from session state; use a callable "
                "InstructionProvider instead (L1-01)."
            ),
            context_name=target.id,
        )
      if target.id == "_ENFORCE_YAML_KEY_DENYLIST" and self._eval_bool(value) is False:
        self._record(
            "L5-03",
            stmt_node,
            "Setting _ENFORCE_YAML_KEY_DENYLIST = False disables YAML key denylist protection and enables RCE (L5-03).",
        )
    elif isinstance(target, ast.Subscript):
      self._check_subscript_assign(target, value, stmt_node)
    elif isinstance(target, ast.Attribute):
      fn_scope = self._scope_names[-1]
      if (
          fn_scope != "<module>"
          and not _FACTORY_FUNC_NAME_RE.match(fn_scope)
          and target.attr in ("instruction", "tools", "sub_agents")
      ):
        owner_str = ast.unparse(target.value)
        if (
            owner_str.endswith(".agent")
            or (
                (
                    owner_str in self._agent_var_names
                    or re.search(r"(?:^|_)agent$", owner_str)
                )
                and owner_str not in self._scope_vars[-1]
                and any(tok in self.source_code for tok in ("google.adk", "LlmAgent", "Agent("))
            )
        ):
          self._record(
              "L5-03",
              stmt_node,
              (
                  f"Runtime mutation of '{owner_str}.{target.attr}' inside "
                  f"'{fn_scope}()' modifies a live ADK agent definition after "
                  "initialization (L5-03)."
              ),
              context_name=fn_scope,
          )

  def visit_Assign(self, node: ast.Assign) -> None:
    for target in node.targets:
      self._track_assignment(target, node.value, node)
    self.generic_visit(node)

  def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
    if node.value is not None:
      self._track_assignment(node.target, node.value, node)
    self.generic_visit(node)

  def visit_AugAssign(self, node: ast.AugAssign) -> None:
    if isinstance(node.target, ast.Name):
      if self._is_tainted_sql(node.value):
        self._tainted_sql_vars[-1].add(node.target.id)
      is_bad_p, _ = self._is_dynamic_or_brace_prompt(node.value)
      if is_bad_p:
        self._tainted_prompt_vars[-1].add(node.target.id)
    self.generic_visit(node)

  def _check_subscript_assign(
      self, target: ast.Subscript, value: ast.expr, stmt_node: ast.AST
  ) -> None:
    resolved_slice = self._resolve(target.slice)
    key_str = self._eval_str(resolved_slice)
    container_str = ast.unparse(target.value)

    if key_str is not None and container_str in ("os.environ", "environ"):
      # (GOOGLE_APPLICATION_CREDENTIALS and runtime-bound token env vars: optional gcp-gemini pack.)
      val_str = (self._eval_str(value) or "").strip()
      if key_str == "ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS":
        if val_str.lower() in ("true", "1", "yes", "on"):
          self._record(
              "L5-02",
              stmt_node,
              "Setting ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS='true' exports unredacted prompts and PII in telemetry spans (L5-02).",
          )

    # Check direct or nested writes into state[...] / ctx.state[...] / tool_context.state[...]
    is_direct_state = (
        container_str == "state" or container_str.endswith(".state")
    )
    is_nested_state = False
    nested_key_desc = ""
    if isinstance(target.value, ast.Subscript):
      outer_container = ast.unparse(target.value.value)
      if outer_container == "state" or outer_container.endswith(".state"):
        is_nested_state = True
        outer_k = self._eval_str(target.value.slice) or ast.unparse(target.value.slice)
        inner_k = key_str or ast.unparse(target.slice)
        nested_key_desc = f"{outer_k}[{inner_k}]"
    elif isinstance(target.value, ast.Call):
      call_fn_str = ast.unparse(target.value.func)
      if call_fn_str == "state.setdefault" or call_fn_str.endswith(".state.setdefault"):
        is_nested_state = True
        outer_k = (
            self._eval_str(target.value.args[0])
            if target.value.args
            else ""
        ) or ""
        inner_k = key_str or ast.unparse(target.slice)
        nested_key_desc = f"{outer_k}[{inner_k}]"

    if is_direct_state or is_nested_state:
      # L1-04: Direct mutation of privileged/internal state key
      if is_direct_state:
        if key_str is not None and _PRIVILEGED_STATE_KEY_RE.match(key_str):
          self._record(
              "L1-04",
              stmt_node,
              (
                  f"Direct mutation of privileged/internal state key '{key_str}' "
                  f"via {container_str}[{key_str!r}] bypasses schema validation "
                  "(L1-04). Validate keys first, for example with validate_state_delta()."
              ),
          )
        elif isinstance(resolved_slice, ast.JoinedStr):
          slice_unp = ast.unparse(resolved_slice)
          if any(
              p in slice_unp
              for p in ("app:", "user:", "auth:", "role:", "_adk_activated_skills_")
          ):
            self._record(
                "L1-04",
                stmt_node,
                (
                    f"Direct mutation of privileged/internal state key {slice_unp} "
                    f"via {container_str}[...] bypasses schema validation "
                    "(L1-04). Validate keys first, for example with validate_state_delta()."
                ),
            )

      # L2-01 (4.2): Plaintext OAuth token/credential caching in state[...]
      if not self._file_has_kms_credential_guard:
        effective_key = (
            nested_key_desc
            if is_nested_state
            else (key_str or ast.unparse(target.slice))
        )
        val_unparsed = ast.unparse(value)
        if self._is_plaintext_token_state_entry(effective_key, value, val_unparsed):
          self._record(
              "L2-01",
              stmt_node,
              (
                  f"Plaintext OAuth token/credential cached in session state "
                  f"({ast.unparse(target)}) without GOOGLE_CREDENTIAL_KMS_KEY "
                  "envelope encryption (L2-01)."
              ),
          )

  def _check_subagent_call(self, sub_node: ast.Call, parent_agent_name: str) -> None:
    """Checks an LlmAgent/Agent used as a sub-agent for L4-01 isolation."""
    if id(sub_node) in self._checked_subagent_nodes:
      return
    self._checked_subagent_nodes.add(id(sub_node))
    sub_name = self._eval_str(_get_kwarg(sub_node, "name")) or "sub_agent"
    inc_val = self._eval_str(_get_kwarg(sub_node, "include_contents"))
    dis_peers = self._eval_bool(_get_kwarg(sub_node, "disallow_transfer_to_peers"))
    for kw in sub_node.keywords:
      if kw.arg is None:
        unpacked = self._resolve(kw.value)
        if isinstance(unpacked, ast.Call) and _get_call_name(unpacked).split(".")[-1] in (
            "get_isolated_subagent_kwargs",
            "create_isolated_subagent_spec",
            "project_subagent_context",
        ):
          if inc_val is None:
            inc_val = self._eval_str(_get_kwarg(unpacked, "include_contents")) or "none"
          if dis_peers is None:
            dis_peers = True
        elif isinstance(unpacked, ast.Dict):
          for k, v in zip(unpacked.keys, unpacked.values):
            if isinstance(k, ast.Constant) and k.value == "include_contents" and inc_val is None:
              inc_val = self._eval_str(v)
            elif (
                isinstance(k, ast.Constant)
                and k.value == "disallow_transfer_to_peers"
                and dis_peers is None
            ):
              dis_peers = self._eval_bool(v)
    if inc_val != "none" or dis_peers is not True:
      missing_parts: list[str] = []
      if inc_val != "none":
        missing_parts.append("include_contents='none'")
      if dis_peers is not True:
        missing_parts.append("disallow_transfer_to_peers=True")
      self._record(
          "L4-01",
          sub_node,
          (
              f"Sub-agent '{sub_name}' (under '{parent_agent_name}') is missing "
              f"{' and '.join(missing_parts)}, allowing full parent conversation "
              "inheritance and peer privilege escalation (L4-01)."
          ),
          context_name=sub_name,
      )

  def visit_Call(self, node: ast.Call) -> None:
    call_name = _get_call_name(node)
    short_name = call_name.split(".")[-1] if call_name else ""

    # Direct Gemini SDK calls (generate_content prompts, model aliases, safety settings, and
    # bypassing ADK callbacks) are checked by the optional gcp-gemini pack.

    # L1-01, L1-02, L1-03, L4-01 on LlmAgent / Agent
    if short_name in ("LlmAgent", "Agent"):
      agent_name = (
          self._eval_str(_get_kwarg(node, "name"))
          or f"{short_name}_L{node.lineno}"
      )

      # L1-01: instruction / static_instruction / global_instruction
      for inst_kw_name in ("instruction", "static_instruction", "global_instruction"):
        inst_arg = _get_kwarg(node, inst_kw_name)
        is_bad, reason = self._is_dynamic_or_brace_prompt(inst_arg)
        if is_bad:
          self._record(
              "L1-01",
              node,
              (
                  f"{short_name} '{agent_name}' uses {reason} in `{inst_kw_name}`, "
                  "enabling indirect prompt injection via ADK session state "
                  "interpolation (L1-01). Use a callable InstructionProvider "
                  "(ctx: ReadonlyContext) that fences untrusted values."
              ),
              context_name=agent_name,
          )

      # L1-02: Unpinned '-latest' or '-exp' model
      model_str = self._eval_str(_get_kwarg(node, "model"))
      if model_str and (
          model_str.endswith("-latest")
          or model_str.endswith("-exp")
          or "latest" in model_str.lower()
      ):
        self._record(
            "L1-02",
            node,
            (
                f"{short_name} '{agent_name}' uses unpinned mutable model alias "
                f"{model_str!r} (L1-02). Pin to an immutable model version and "
                "set safety_settings via generate_content_config."
            ),
            context_name=agent_name,
        )

      # L1-03: Missing before_model_callback on LlmAgent/Agent
      bmc_kw = _get_kwarg(node, "before_model_callback")
      bmc_resolved = self._resolve(bmc_kw)
      bac_kw = _get_kwarg(node, "before_agent_callback")
      bac_resolved = self._resolve(bac_kw)
      has_agent_cb = (
          bmc_kw is not None
          and not (isinstance(bmc_resolved, ast.Constant) and bmc_resolved.value is None)
      ) or (
          bac_kw is not None
          and not (isinstance(bac_resolved, ast.Constant) and bac_resolved.value is None)
      )
      assigned_var = self._call_var_names.get(id(node))
      is_runner_guarded = (
          id(node) in self._runner_guarded_agent_nodes
          or (assigned_var is not None and assigned_var in self._runner_guarded_agent_vars)
      )
      if not has_agent_cb and not self._file_has_model_armor_plugin and not is_runner_guarded:
        self._record(
            "L1-03",
            node,
            (
                f"{short_name} '{agent_name}' is missing `before_model_callback` "
                "and no ModelArmorPlugin is registered (L1-03)."
            ),
            context_name=agent_name,
        )

      # L3-02, L4-01 (AgentTool) in tools=[...]
      tools_kw = self._resolve(_get_kwarg(node, "tools"))
      if isinstance(tools_kw, (ast.List, ast.Tuple)):
        has_untrusted_toolset = False
        for elt in tools_kw.elts:
          resolved_elt = self._resolve(elt)
          if isinstance(resolved_elt, ast.Call):
            t_sname = _get_call_name(resolved_elt).split(".")[-1]
            if t_sname in ("LoadMcpResourceTool", "McpToolset", "MCPToolset"):
              has_untrusted_toolset = True
            elif t_sname == "AgentTool":
              sub_ag_expr = (
                  resolved_elt.args[0]
                  if resolved_elt.args
                  else _get_kwarg(resolved_elt, "agent")
              )
              resolved_sub_ag = self._resolve(sub_ag_expr)
              if isinstance(resolved_sub_ag, ast.Call):
                sub_sname = _get_call_name(resolved_sub_ag).split(".")[-1]
                if sub_sname in ("LlmAgent", "Agent"):
                  self._check_subagent_call(resolved_sub_ag, agent_name)
              elif sub_ag_expr is not None and not any(
                  g in self.source_code
                  for g in (
                      "create_isolated_subagent_spec",
                      "get_isolated_subagent_kwargs",
                  )
              ):
                self._record(
                    "L4-01",
                    resolved_elt,
                    (
                        f"AgentTool in '{agent_name}' wraps sub-agent "
                        f"'{ast.unparse(sub_ag_expr)}' without verified "
                        "`include_contents='none'` and `disallow_transfer_to_peers=True` "
                        "isolation (L4-01)."
                    ),
                    context_name=agent_name,
                )
        atc_kw = _get_kwarg(node, "after_tool_callback")
        if has_untrusted_toolset and atc_kw is None and not self._file_has_after_tool_guard:
          self._record(
              "L3-02",
              node,
              (
                  f"{short_name} '{agent_name}' registers untrusted MCP/retrieval "
                  "tools without `after_tool_callback` (for example a `wrap_tool_output` "
                  "helper that fences tool output) (L3-02)."
              ),
              context_name=agent_name,
          )

      # L4-01: Sub-agents in sub_agents=[...]
      sub_kw = _get_kwarg(node, "sub_agents")
      resolved_sub = self._resolve(sub_kw)
      if isinstance(resolved_sub, (ast.List, ast.Tuple)):
        for elt in resolved_sub.elts:
          resolved_elt = self._resolve(elt)
          if isinstance(resolved_elt, ast.Call):
            elt_sname = _get_call_name(resolved_elt).split(".")[-1]
            if elt_sname in ("LlmAgent", "Agent"):
              self._check_subagent_call(resolved_elt, agent_name)

    # L1-01: inject_session_state(..., use_jinja2=True)
    if short_name == "inject_session_state":
      jinja_kw = _get_kwarg(node, "use_jinja2")
      if self._eval_bool(jinja_kw) is True:
        self._record(
            "L1-01",
            node,
            "inject_session_state(..., use_jinja2=True) enables Server-Side Template Injection (SSTI) (L1-01).",
        )

    # Gemini SafetySetting / GenerateContentConfig thresholds are checked by the optional gcp-gemini pack.

    # L1-03: ModelArmorConfig templates, App, Runner
    # (Hand-rolled Model Armor clients are checked by the optional gcp-gemini pack.)
    if short_name == "ModelArmorConfig":
      for tmpl_arg in ("prompt_template_name", "response_template_name", "template_id", "prompt_template"):
        kw_val = _get_kwarg(node, tmpl_arg)
        if kw_val is not None:
          resolved_val = self._resolve(kw_val)
          if (
              isinstance(resolved_val, ast.Constant)
              and (resolved_val.value is None or str(resolved_val.value).strip() == "")
          ):
            self._record(
                "L1-03",
                node,
                f"{short_name} configured with empty/None `{tmpl_arg}` disables inline prompt-injection screening (L1-03).",
            )
    elif short_name == "App":
      root_ag_kw = _get_kwarg(node, "root_agent")
      if root_ag_kw is not None:
        if not self._has_nonempty_plugins(node) and not self._agent_expr_has_guardrail(root_ag_kw):
          app_name = self._eval_str(_get_kwarg(node, "name")) or "App"
          self._record(
              "L1-03",
              node,
              (
                  f"App '{app_name}' instantiated with root_agent without "
                  "security plugins=[...] (ModelArmorPlugin & ToolCallIntegrityPlugin) "
                  "(L1-03)."
              ),
              context_name=app_name,
          )
    elif short_name in ("Runner", "InMemoryRunner"):
      if not self._has_nonempty_plugins(node):
        app_kw = self._resolve(_get_kwarg(node, "app"))
        app_provides_plugins = False
        if (
            isinstance(app_kw, ast.Call)
            and _get_call_name(app_kw).split(".")[-1] == "App"
        ):
          if self._has_nonempty_plugins(app_kw) or self._agent_expr_has_guardrail(
              _get_kwarg(app_kw, "root_agent")
          ):
            app_provides_plugins = True
        if not app_provides_plugins:
          self._record(
              "L1-03",
              node,
              f"{short_name} instantiated without security plugins (ModelArmorPlugin, ToolCallIntegrityPlugin) (L1-03).",
          )

    # Gap 1c: EventActions(state_delta=...)
    if short_name == "EventActions":
      sd_kw = _get_kwarg(node, "state_delta")
      if sd_kw is not None:
        sd_unparsed = ast.unparse(sd_kw)
        resolved_sd = self._resolve(sd_kw)
        resolved_unparsed = ast.unparse(resolved_sd) if resolved_sd is not None else ""
        is_wrapped_safe = any(
            g in sd_unparsed or g in resolved_unparsed
            for g in ("validate_state_delta",)
        )
        is_empty_or_none = (
            isinstance(resolved_sd, ast.Constant) and resolved_sd.value is None
        ) or (isinstance(resolved_sd, ast.Dict) and not resolved_sd.keys)
        if not is_empty_or_none:
          priv_keys: list[str] = []
          if isinstance(resolved_sd, ast.Dict):
            for k in resolved_sd.keys:
              k_str = self._eval_str(k)
              if k_str and _PRIVILEGED_STATE_KEY_RE.match(k_str):
                priv_keys.append(k_str)
              elif isinstance(k, ast.JoinedStr):
                k_unp = ast.unparse(k)
                if any(
                    p in k_unp
                    for p in ("app:", "user:", "auth:", "role:", "_adk_activated_skills_")
                ):
                  priv_keys.append(k_unp)
          if priv_keys:
            self._record(
                "L1-04",
                node,
                (
                    f"EventActions(state_delta=...) mutates privileged/internal "
                    f"state key(s) {priv_keys} without validation such as validate_state_delta() (L1-04)."
                ),
            )
          elif not is_wrapped_safe:
            self._record(
                "L1-04",
                node,
                (
                    "EventActions(state_delta=...) passes an unvalidated state_delta "
                    "mapping without key validation such as validate_state_delta() (L1-04)."
                ),
            )
          if isinstance(resolved_sd, ast.Dict) and not self._file_has_kms_credential_guard:
            for k, v in zip(resolved_sd.keys, resolved_sd.values):
              k_str = self._eval_str(k) or (ast.unparse(k) if k is not None else "")
              v_str = ast.unparse(v) if v is not None else ""
              if self._is_plaintext_token_state_entry(k_str, v, v_str):
                self._record(
                    "L2-01",
                    node,
                    (
                        f"EventActions(state_delta=...) caches plaintext OAuth "
                        f"token/credential in '{k_str}' without "
                        "GOOGLE_CREDENTIAL_KMS_KEY envelope encryption (L2-01)."
                    ),
                )
                break

    # L1-04 / L4-01 / L2-01: state.update(...)
    if (
        (call_name == "state.update" or call_name.endswith(".state.update"))
        and node.args
    ):
      arg0 = self._resolve(node.args[0])
      if isinstance(arg0, ast.Dict):
        for k, v in zip(arg0.keys, arg0.values):
          k_str = self._eval_str(k)
          if k_str and _PRIVILEGED_STATE_KEY_RE.match(k_str):
            self._record(
                "L1-04",
                node,
                f"Direct .state.update() of privileged key '{k_str}' bypasses validation such as validate_state_delta() (L1-04).",
            )
          if not self._file_has_kms_credential_guard:
            eff_k = k_str or (ast.unparse(k) if k is not None else "")
            v_str = ast.unparse(v) if v is not None else ""
            if self._is_plaintext_token_state_entry(eff_k, v, v_str):
              self._record(
                  "L2-01",
                  node,
                  f"Direct .state.update() caches plaintext OAuth token/credential in '{eff_k}' without GOOGLE_CREDENTIAL_KMS_KEY (L2-01).",
              )
      else:
        arg0_unparsed = ast.unparse(node.args[0])
        if "state_delta" in arg0_unparsed and "validate_state_delta" not in arg0_unparsed:
          self._record(
              "L4-01",
              node,
              f"Unfiltered state.update({arg0_unparsed}) allows child sub-agent or client state_delta to overwrite privileged parent state (L4-01).",
          )

    # L2-01: SessionStateCredentialService / ToolContextCredentialStore without KMS, or OAuth2 without S256
    if short_name in ("SessionStateCredentialService", "ToolContextCredentialStore"):
      kms_kw = _get_kwarg(node, "kms_key_name") or _get_kwarg(node, "encryption_key")
      if kms_kw is None or (
          isinstance(self._resolve(kms_kw), ast.Constant)
          and not self._eval_str(kms_kw)
      ):
        self._record(
            "L2-01",
            node,
            f"{short_name} instantiated without KMS envelope encryption (`GOOGLE_CREDENTIAL_KMS_KEY`) stores plaintext OAuth tokens in session state (L2-01).",
        )
    elif short_name in ("OAuth2Auth", "AuthConfig", "OAuthConfig"):
      ccm_kw = _get_kwarg(node, "code_challenge_method")
      if ccm_kw is not None and self._eval_str(ccm_kw) != "S256":
        self._record(
            "L2-01",
            node,
            f"{short_name} uses weak or disabled PKCE code_challenge_method={ast.unparse(ccm_kw)} instead of 'S256' (L2-01).",
        )

    # L2-02: list_sessions(..., user_id=None)
    if short_name == "list_sessions":
      uid_kw = _get_kwarg(node, "user_id")
      resolved_uid = self._resolve(uid_kw)
      if uid_kw is None or (isinstance(resolved_uid, ast.Constant) and resolved_uid.value is None):
        self._record(
            "L2-02",
            node,
            "Calling list_sessions(..., user_id=None) enumerates sessions across all tenants (L2-02).",
        )

    # L2-03: get_fast_api_app, TriggerRouter, GoogleOidcVerifier
    # (CORSMiddleware and auth on custom FastAPI routes are generic web checks for a general SAST tool.
    # MCP SDK TransportSecuritySettings with DNS-rebinding protection disabled is checked by the
    # optional mcp pack.)
    if short_name == "get_fast_api_app":
      web_val = self._eval_bool(_get_kwarg(node, "web"))
      origins_kw = self._resolve(_get_kwarg(node, "allow_origins"))
      has_wildcard = False
      if origins_kw is not None:
        origins_str = ast.unparse(origins_kw)
        if '"*"' in origins_str or "'*'" in origins_str:
          has_wildcard = True
      if web_val is True or has_wildcard:
        self._record(
            "L2-03",
            node,
            f"{short_name} configured with unauthenticated web=True or wildcard allow_origins=['*'] (L2-03).",
        )
      if short_name == "get_fast_api_app":
        ts_kw = self._resolve(_get_kwarg(node, "trigger_sources"))
        if ts_kw is not None:
          is_empty_ts = (
              isinstance(ts_kw, ast.Constant) and not ts_kw.value
          ) or (
              isinstance(ts_kw, (ast.List, ast.Tuple, ast.Set, ast.Dict))
              and len(getattr(ts_kw, "elts", getattr(ts_kw, "keys", []))) == 0
          )
          verifier_kw = self._resolve(_get_kwarg(node, "trigger_auth_verifier"))
          has_custom_verifier = verifier_kw is not None and not (
              isinstance(verifier_kw, ast.Constant) and verifier_kw.value is None
          )
          audience = self._eval_str(_get_kwarg(node, "trigger_oidc_audience"))
          aud_kw = self._resolve(_get_kwarg(node, "trigger_oidc_audience"))
          has_audience = bool(audience) or (
              aud_kw is not None and not isinstance(aud_kw, ast.Constant)
          )
          if (
              not is_empty_ts
              and not self._file_has_trigger_oidc_verifier
              and not has_custom_verifier
              and not has_audience
          ):
            self._record(
                "L2-03",
                node,
                (
                    "get_fast_api_app() configured with trigger_sources without "
                    "trigger_oidc_audience, trigger_auth_verifier, or a GoogleOidcVerifier "
                    "exposes unauthenticated /apps/{app}/trigger/* endpoints (L2-03)."
                ),
            )
          elif not is_empty_ts and has_audience and not has_custom_verifier:
            sas_kw = self._resolve(_get_kwarg(node, "trigger_oidc_service_accounts"))
            if sas_kw is None or (
                isinstance(sas_kw, ast.Constant) and sas_kw.value is None
            ) or (isinstance(sas_kw, (ast.List, ast.Tuple, ast.Set)) and not sas_kw.elts):
              self._record(
                  "L2-03",
                  node,
                  (
                      "get_fast_api_app(trigger_oidc_audience=...) without a non-empty "
                      "trigger_oidc_service_accounts allowlist accepts any Google-signed "
                      "OIDC token for the audience on /trigger/* endpoints (L2-03)."
                  ),
              )
    elif short_name == "TriggerRouter":
      ver_kw = _get_kwarg(node, "verifier")
      resolved_ver = self._resolve(ver_kw)
      if ver_kw is None or (isinstance(resolved_ver, ast.Constant) and resolved_ver.value is None):
        self._record(
            "L2-03",
            node,
            "TriggerRouter instantiated with verifier=None exposes unauthenticated webhook/PubSub triggers (L2-03).",
        )
    elif short_name == "GoogleOidcVerifier":
      # Signature: GoogleOidcVerifier(audience, allowed_emails=None).
      ae_expr = node.args[1] if len(node.args) > 1 else _get_kwarg(node, "allowed_emails")
      ae_kw = self._resolve(ae_expr)
      if ae_kw is None or (isinstance(ae_kw, ast.Constant) and ae_kw.value is None) or (
          isinstance(ae_kw, (ast.List, ast.Tuple, ast.Set)) and len(ae_kw.elts) == 0
      ):
        self._record(
            "L2-03",
            node,
            (
                "GoogleOidcVerifier configured without a non-empty allowed_emails allowlist "
                "accepts any Google-signed OIDC token for the audience (L2-03)."
            ),
        )

    # L3-01: FunctionTool, ApplicationIntegrationToolset, GCSAdminToolset without confirmation / tool_filter
    if short_name == "FunctionTool":
      fn_expr = node.args[0] if node.args else _get_kwarg(node, "func")
      if isinstance(fn_expr, ast.Name):
        fn_name = fn_expr.id
      elif isinstance(fn_expr, ast.Attribute):
        fn_name = fn_expr.attr
      else:
        fn_name = ""
      req_conf_expr = _get_kwarg(node, "require_confirmation")
      req_conf_val = self._eval_bool(req_conf_expr)
      resolved_rc = self._resolve(req_conf_expr)
      has_callable_or_true_rc = (
          req_conf_val is True
          or (
              resolved_rc is not None
              and not (
                  isinstance(resolved_rc, ast.Constant)
                  and resolved_rc.value in (False, None)
              )
              and req_conf_val is not False
          )
      )
      if req_conf_val is False:
        self._record(
            "L3-01",
            node,
            f"FunctionTool({fn_name or '...'}) resolves require_confirmation=False, disabling HITL confirmation (L3-01).",
            context_name=fn_name or None,
        )
      elif (
          fn_name
          and _MUTATING_TOOL_PREFIX_RE.match(fn_name)
          and not has_callable_or_true_rc
          and fn_name not in self._confirmed_tool_funcs
      ):
        self._record(
            "L3-01",
            node,
            f"State-mutating FunctionTool '{fn_name}' is registered without require_confirmation=True (L3-01).",
            context_name=fn_name,
        )
    elif short_name == "ApplicationIntegrationToolset":
      rc_val = self._eval_bool(_get_kwarg(node, "require_confirmation"))
      node_unparsed = ast.unparse(node)
      for kw in node.keywords:
        resolved_kw = self._resolve(kw.value)
        if resolved_kw is not None:
          node_unparsed += " " + ast.unparse(resolved_kw)
      has_write_ops = any(
          op in node_unparsed
          for op in (
              "CREATE_ENTITY",
              "UPDATE_ENTITY",
              "DELETE_ENTITY",
              '"*"',
              "'*'",
              "CREATE",
              "UPDATE",
              "DELETE",
          )
      )
      if has_write_ops and rc_val is not True:
        self._record(
            "L3-01",
            node,
            "ApplicationIntegrationToolset enables write/wildcard operations (CREATE_ENTITY/UPDATE_ENTITY/DELETE_ENTITY/actions=['*']) without require_confirmation=True (L3-01).",
        )
    elif short_name == "GCSAdminToolset":
      # GCSAdminToolset has no require_confirmation option; constrain it with a read-only tool_filter.
      filter_kw = self._resolve(_get_kwarg(node, "tool_filter"))
      if filter_kw is None or (
          isinstance(filter_kw, ast.Constant) and filter_kw.value is None
      ):
        self._record(
            "L3-01",
            node,
            "GCSAdminToolset exposes bucket/object administration to the LLM without a `tool_filter` allowlist of read-only tools (L3-01).",
        )

    # L3-02: LoadMcpResourceTool without an after_tool_callback output guard
    # (raw exception text and traceback.format_exc() leaks are left to a general SAST tool.)
    if short_name == "LoadMcpResourceTool" and not self._file_has_after_tool_guard:
      self._record(
          "L3-02",
          node,
          "LoadMcpResourceTool instantiated without an after_tool_callback that fences untrusted resource output (for example a wrap_tool_output() helper) (L3-02).",
      )

    # L3-03: BigQueryToolConfig, SpannerAdminToolset, OpenAPIToolset, RestApiTool, MCP subprocess env and pinning
    # (SQL injection in hand-written queries is left to a general SAST tool.)
    if short_name == "BigQueryToolConfig":
      wm_kw = self._resolve(_get_kwarg(node, "write_mode"))
      if wm_kw is not None and "ALLOWED" in ast.unparse(wm_kw):
        self._record(
            "L3-03",
            node,
            "BigQueryToolConfig(write_mode=WriteMode.ALLOWED) permits arbitrary DDL/DML mutations by the LLM (L3-03).",
        )
    elif short_name == "SpannerAdminToolset":
      self._record(
          "L3-03",
          node,
          "SpannerAdminToolset grants database DDL/instance administration capabilities to the LLM (L3-03).",
      )
    elif short_name in ("OpenAPIToolset", "RestApiTool"):
      tf_kw = _get_kwarg(node, "tool_filter")
      rc_kw = _get_kwarg(node, "require_confirmation")
      if tf_kw is None and rc_kw is None:
        self._record(
            "L3-03",
            node,
            f"{short_name} instantiated without `tool_filter` allowlist or `require_confirmation`, exposing unconstrained REST endpoints to the LLM (L3-03).",
        )
    elif short_name in ("McpToolset", "MCPToolset", "StdioServerParameters", "StdioConnectionParams"):
      env_kw = self._resolve(_get_kwarg(node, "env"))
      if env_kw is not None and "environ" in ast.unparse(env_kw):
        self._record(
            "L3-03",
            node,
            f"{short_name} passes ambient os.environ credentials to external MCP subprocess (L3-03).",
        )
      args_kw = self._resolve(_get_kwarg(node, "args"))
      has_cli_secret = False
      if isinstance(args_kw, (ast.List, ast.Tuple)):
        for elt in args_kw.elts:
          elt_str = self._extract_leading_arg_str(elt)
          if elt_str and _MCP_CLI_SECRET_ARG_RE.match(elt_str):
            has_cli_secret = True
            self._record(
                "L3-03",
                node,
                f"{short_name} passes credential flag '{elt_str.split('=')[0]}' via CLI args instead of an allowlisted env map (L3-03).",
            )
            break
      if not has_cli_secret:
        node_str = ast.unparse(node)
        launches_package = bool(re.search(r"\b(npx|uvx|pipx|bunx)\b", node_str))
        if (
            "@latest" in node_str
            or re.search(r"""['"](?:-y|--yes)['"]""", node_str)
            or (launches_package and not re.search(r"(?:@|==)\d", node_str))
        ):
          self._record(
              "L3-03",
              node,
              f"{short_name} launches an MCP server from an unpinned package (`-y`, `@latest`, or no `@x.y.z` / `==x.y.z` version); pin the exact package version (L3-03).",
          )

    # L3-04: ComputerUseToolset browser navigation without network interception.
    # (SSRF in custom requests/httpx/aiohttp/urllib code is left to a general SAST tool.)
    if short_name == "ComputerUseToolset" and ".route(" not in self.source_code:
      self._record(
          "L3-04",
          node,
          "ComputerUseToolset lets the model navigate a browser to arbitrary URLs without a `page.route` destination allowlist (L3-04).",
      )

    # L3-05: LocalEnvironment, RunSkillScriptTool, SkillToolset
    if short_name == "LocalEnvironment":
      self._record(
          "L3-05",
          node,
          "LocalEnvironment executes skill scripts on the host with ambient environment variables (L3-05).",
      )
    elif short_name in ("RunSkillScriptTool", "SkillToolset"):
      exec_kw = self._resolve(_get_kwarg(node, "code_executor"))
      env_kw = self._resolve(_get_kwarg(node, "environment"))
      exec_str = ast.unparse(exec_kw) if exec_kw is not None else ""
      env_str = ast.unparse(env_kw) if env_kw is not None else ""
      combined_env_exec = f"{exec_str} {env_str}"
      has_local_env = "LocalEnvironment" in combined_env_exec
      has_safe_sandbox = (
          self._file_has_sandbox_executor
          or any(
              sb in combined_env_exec
              for sb in (
                  "E2BEnvironment",
                  "AgentEngineSandboxCodeExecutor",
                  "GkeCodeExecutor",
                  "VertexAiCodeExecutor",
              )
          )
      )
      is_prompt_only_skills = (
          short_name == "SkillToolset"
          and not has_local_env
          and self._are_skills_prompt_only(node)
      )
      if has_local_env or (not has_safe_sandbox and not is_prompt_only_skills):
        self._record(
            "L3-05",
            node,
            f"{short_name} allows host skill script execution without a sandboxed code executor (AgentEngineSandboxCodeExecutor, GkeCodeExecutor) (L3-05).",
        )

    # L4-02: RemoteA2aAgent or to_a2a()
    if short_name == "to_a2a":
      self._record(
          "L4-02",
          node,
          "to_a2a() exposes an unauthenticated A2A server endpoint without OIDC/mTLS verification (L4-02).",
      )
    elif short_name == "RemoteA2aAgent":
      fh_val = self._eval_bool(_get_kwarg(node, "full_history_when_stateless"))
      card_val = self._eval_str(
          node.args[1] if len(node.args) > 1 else _get_kwarg(node, "agent_card")
      )
      if fh_val is True or (card_val and card_val.startswith("http://")):
        self._record(
            "L4-02",
            node,
            (
                "RemoteA2aAgent configured with full_history_when_stateless=True "
                "(sends full conversation history to a stateless remote agent) "
                "or a plaintext http:// agent_card (L4-02)."
            ),
        )
    elif short_name == "A2aRemoteAgentConfig":
      fs_val = self._eval_bool(_get_kwarg(node, "forward_session_id_as_context_id"))
      if fs_val is True:
        self._record(
            "L4-02",
            node,
            (
                "A2aRemoteAgentConfig(forward_session_id_as_context_id=True) forwards the raw "
                "local session ID as the remote context_id; use False or \"namespaced\" (L4-02)."
            ),
        )

    # L4-03: Unsandboxed ADK code executors.
    # (eval/exec/os.system/pickle in custom code are left to a general SAST tool.)
    if short_name in (
        "UnsafeLocalCodeExecutor",
        "BuiltInCodeExecutor",
        "ContainerCodeExecutor",
    ):
      self._record(
          "L4-03",
          node,
          f"Unsandboxed or shared code executor '{short_name}' detected (L4-03). Use ephemeral microVM or gVisor sandbox.",
      )

    # L4-04: SaveFilesAsArtifactsPlugin or unsanitized save_artifact() names.
    # (GCS bucket/blob checks live in the optional gcp-gemini pack; open() path traversal is left to a general SAST tool.)
    if short_name == "SaveFilesAsArtifactsPlugin":
      self._record(
          "L4-04",
          node,
          "SaveFilesAsArtifactsPlugin persists user uploads without basename path-traversal or magic-byte validation (L4-04).",
      )
    elif short_name == "save_artifact":
      name_node = node.args[0] if node.args else _get_kwarg(node, "filename")
      name_str = ast.unparse(name_node) if name_node is not None else ""
      uses_param = name_node is not None and any(
          isinstance(n, ast.Name)
          and (
              n.id in self._func_param_names[-1]
              or n.id in self._tainted_param_vars[-1]
          )
          for n in ast.walk(name_node)
      )
      if uses_param and "basename" not in name_str:
        self._record(
            "L4-04",
            node,
            f"save_artifact() name '{name_str}' comes from a function parameter without os.path.basename() sanitization or 'user:'/'app:' scope-prefix checks (L4-04).",
        )

    # L4-05: VertexAiRagMemoryService without FailClosedRagMemoryGuard
    if short_name == "VertexAiRagMemoryService" and "FailClosedRagMemoryGuard" not in self._class_stack:
      self._record(
          "L4-05",
          node,
          "Direct VertexAiRagMemoryService instantiation bypasses the >1,000-file fail-closed tenant filter guard (L4-05).",
      )

    # L5-01: RunConfig without max_llm_calls, LoopAgent without max_iterations, or GLOBAL retry tracking
    if short_name == "RunConfig":
      is_non_adk_run_config = (
          self._non_adk_run_config_imported
          or "tau_bench" in call_name
          or _get_kwarg(node, "model_provider") is not None
          or _get_kwarg(node, "user_model") is not None
          or _get_kwarg(node, "agent_strategy") is not None
      )
      if not is_non_adk_run_config:
        max_calls_kw = _get_kwarg(node, "max_llm_calls")
        if max_calls_kw is None:
          self._record(
              "L5-01",
              node,
              "RunConfig instantiated without explicit `max_llm_calls` bound (1..50) (L5-01).",
          )
        else:
          max_val = self._eval_int(max_calls_kw)
          if max_val is not None and (max_val <= 0 or max_val > 50):
            self._record(
                "L5-01",
                node,
                f"RunConfig(max_llm_calls={max_val}) violates the 1..50 turn ceiling and enables Denial-of-Wallet loops (L5-01).",
            )
    elif short_name == "LoopAgent":
      max_iter_kw = _get_kwarg(node, "max_iterations")
      if max_iter_kw is None:
        self._record(
            "L5-01",
            node,
            "LoopAgent instantiated without `max_iterations` bound, enabling unbounded agent loop execution (L5-01).",
        )
      else:
        max_iter_val = self._eval_int(max_iter_kw)
        if max_iter_val is not None and max_iter_val <= 0:
          self._record(
              "L5-01",
              node,
              f"LoopAgent(max_iterations={max_iter_val}) disables loop termination and enables unbounded execution (L5-01).",
          )
        elif max_iter_val is not None and max_iter_val > 25:
          self._record(
              "L5-01",
              node,
              f"LoopAgent(max_iterations={max_iter_val}) exceeds the recommended 25-iteration threshold; verify loop budget guard (L5-01).",
              status="VERIFY_MITIGATION",
          )
    elif short_name == "ReflectAndRetryToolPlugin":
      ts_kw = self._resolve(_get_kwarg(node, "tracking_scope"))
      if ts_kw is not None and "GLOBAL" in ast.unparse(ts_kw):
        self._record(
            "L5-01",
            node,
            "ReflectAndRetryToolPlugin with TrackingScope.GLOBAL shares failure state across tenants (L5-01).",
        )

    # L5-02: LoggingPlugin / DebugLoggingPlugin export raw prompts and tool payloads.
    # (Secrets written by application logging calls are left to a general SAST tool.)
    if short_name in ("LoggingPlugin", "DebugLoggingPlugin"):
      self._record(
          "L5-02",
          node,
          f"{short_name} dumps unredacted prompts, tool arguments, and tokens to logs (L5-02).",
      )

    # L5-03: Dynamic ADK service registry mutation or runtime agent toolset/sub_agents mutation.
    # (yaml.load / yaml.unsafe_load deserialization in custom code is left to a general SAST tool.)
    if short_name in (
        "register_memory_service",
        "register_session_service",
        "register_artifact_service",
        "register_credential_service",
    ) or (
        short_name.startswith("register_")
        and "service_registry" in ast.unparse(node.func).lower()
    ):
      self._record(
          "L5-03",
          node,
          f"Dynamic service registry mutation via '{call_name}(...)' registers a service factory at runtime; register only allowlisted service URIs (L5-03).",
      )
    elif (
        self._scope_names[-1] != "<module>"
        and not _FACTORY_FUNC_NAME_RE.match(self._scope_names[-1])
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("append", "extend", "insert")
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr in ("tools", "sub_agents")
        and any(tok in self.source_code for tok in ("google.adk", "LlmAgent", "Agent("))
    ):
      owner_expr = node.func.value.value
      owner_str = ast.unparse(owner_expr)
      if not (isinstance(owner_expr, ast.Name) and owner_expr.id in self._scope_vars[-1]):
        self._record(
            "L5-03",
            node,
            (
                f"Runtime agent mutation '{owner_str}.{node.func.value.attr}.{node.func.attr}(...)' "
                f"inside '{self._scope_names[-1]}()' modifies a live ADK agent after initialization (L5-03)."
            ),
            context_name=self._scope_names[-1],
        )

    # L5-04: Deployment bundles the repository root via extra_packages=["."].
    # (Static service-account keys, GOOGLE_APPLICATION_CREDENTIALS, runtime-bound token env vars, and
    # secrets in deploy env_vars are checked by the optional gcp-gemini pack.)
    extra_pkg_kw = self._resolve(_get_kwarg(node, "extra_packages"))
    for kw in node.keywords:
      if kw.arg is None:
        unpacked = self._resolve(kw.value)
        if isinstance(unpacked, ast.Dict):
          for uk, uv in zip(unpacked.keys, unpacked.values):
            uk_str = self._eval_str(uk)
            if uk_str == "extra_packages" and extra_pkg_kw is None:
              extra_pkg_kw = self._resolve(uv)
    if isinstance(extra_pkg_kw, (ast.List, ast.Tuple)):
      for elt in extra_pkg_kw.elts:
        pkg_str = self._eval_str(elt)
        if pkg_str in (".", "./", ".."):
          self._record(
              "L5-04",
              node,
              f"Deployment configuration bundles root directory extra_packages=[{pkg_str!r}], leaking .env and tests (L5-04).",
          )

    self.generic_visit(node)


def _scan_config_or_tf_file(
    path: Path, rel_path: str = ""
) -> list[tuple[str, str, int, str, str]]:
  """Scans YAML, JSON, Markdown skill frontmatter/body, and Terraform files via `rules/adk-core.yaml`."""
  del rel_path
  if path.name in ("adk-security-rules.yaml", ".pre-commit-config.yaml") or "cloudbuild" in path.name.lower():
    return []
  return [
      (c_id, st, ln, fn_ag, msg)
      for _rel_f, c_id, st, ln, fn_ag, msg in _run_external_grep_engine(
          path, engine="hybrid", rules_yaml=SEMGREP_RULES_YAML_PATH
      )
  ]


scan_config_file = _scan_config_or_tf_file


def _parse_threat_model_links(threat_model_path: Path | None) -> dict[str, list[str]]:
  """Maps control IDs and OWASP ASI codes to `TM-XX` IDs from THREAT_MODEL.md."""
  mapping: dict[str, list[str]] = {}
  if threat_model_path is None or not threat_model_path.is_file():
    return mapping
  try:
    text = threat_model_path.read_text(encoding="utf-8")
  except (OSError, UnicodeDecodeError):
    return mapping

  # Match lines or sections containing TM-01..TM-99
  for line in text.splitlines():
    tm_ids = re.findall(r"\bTM-\d{2,3}\b", line)
    if not tm_ids:
      continue
    controls = re.findall(r"\bL[1-5]-0[1-5]\b", line)
    asis = re.findall(r"\bASI(?:0[1-9]|10)\b", line)
    for key in controls + asis:
      bucket = mapping.setdefault(key, [])
      for tm_id in tm_ids:
        if tm_id not in bucket:
          bucket.append(tm_id)
  return mapping


@dataclass(frozen=True)
class SuppressionRule:
  """One row of the THREAT_MODEL.md Section 6.4 scanner calibration table."""

  suppression_id: str
  path_glob: str
  controls: frozenset[str]
  action: str
  justification: str
  path_regex: re.Pattern[str]

  def matches(self, rel_path: str, control_id: str, rule_id: str, engine_rule: str) -> bool:
    if not self.path_regex.match(rel_path.replace(os.sep, "/")):
      return False
    if "*" in self.controls:
      return True
    candidates = {_normalize_suppression_target(v) for v in (control_id, rule_id, engine_rule) if v}
    return bool(candidates & self.controls)


def _normalize_suppression_target(value: str) -> str:
  """Upper-cases control IDs (`l1-01` -> `L1-01`) and lower-cases rule IDs."""
  value = value.strip().strip("`")
  if _CONTROL_ID_RE.fullmatch(value):
    return value.upper()
  return value.lower()


def _glob_to_regex(glob: str) -> re.Pattern[str]:
  """Converts a `**`-aware path glob (relative to the scan root) into an anchored regex."""
  glob = glob.strip().replace("\\", "/")
  while glob.startswith("./"):
    glob = glob[2:]
  glob = glob.lstrip("/")
  out: list[str] = []
  i = 0
  while i < len(glob):
    if glob.startswith("**/", i):
      out.append("(?:.*/)?")
      i += 3
    elif glob.startswith("**", i):
      out.append(".*")
      i += 2
    elif glob[i] == "*":
      out.append("[^/]*")
      i += 1
    elif glob[i] == "?":
      out.append("[^/]")
      i += 1
    else:
      out.append(re.escape(glob[i]))
      i += 1
  if glob.endswith("/"):
    out.append(".*")
  return re.compile("^" + "".join(out) + "$")


def _split_md_row(line: str) -> list[str]:
  cells = line.strip().strip("|").split("|")
  return [c.strip().strip("`").strip() for c in cells]


def _parse_threat_model_suppressions(
    threat_model_path: Path | None,
) -> tuple[list[SuppressionRule], list[str]]:
  """Parses the Section 6.4 suppression table in THREAT_MODEL.md.

  Expected columns (order-independent, matched by header name):
  `Suppression ID | Path Glob | Controls | Action | Justification`.
  `Controls` is `*` or a comma-separated list of control IDs (`L4-01`) or rule IDs.
  `Action` is `EXCLUDE` or `VERIFY_MITIGATION`. Rows without an ID, glob, valid action,
  or justification are rejected and reported as warnings.
  """
  rules: list[SuppressionRule] = []
  warnings: list[str] = []
  if threat_model_path is None or not threat_model_path.is_file():
    return rules, warnings
  try:
    lines = threat_model_path.read_text(encoding="utf-8").splitlines()
  except (OSError, UnicodeDecodeError):
    return rules, warnings

  in_section = False
  section_level = 0
  in_fence = False
  table_done = False
  header: list[str] | None = None
  saw_separator = False
  for line in lines:
    stripped = line.strip()
    if stripped.startswith("```"):
      if in_section:
        in_fence = not in_fence
      continue
    if in_fence:
      continue
    if stripped.startswith("#"):
      m_hdr = re.match(r"^(#{1,6})\s+(.*)$", stripped)
      lvl = len(m_hdr.group(1)) if m_hdr else 1
      title = m_hdr.group(2) if m_hdr else stripped.lstrip("#").strip()
      is_sup_hdr = (
          not re.search(r"\b6\.[0-35-9]\b", title)
          and bool(
              re.search(r"\b6\.4\b", title)
              or re.search(
                  r"false[- ]positive suppression|suppression rules|explicit non[- ]goals",
                  title,
                  re.IGNORECASE,
              )
          )
      )
      if not in_section:
        if is_sup_hdr:
          in_section = True
          section_level = lvl
      else:
        if header is not None:
          if lvl <= section_level:
            break
          table_done = True
        else:
          if re.search(r"\b6\.[0-35-9]\b", title):
            in_section = False
            section_level = 0
          elif lvl <= section_level:
            in_section = is_sup_hdr
            section_level = lvl if is_sup_hdr else 0
          elif re.search(r"\b6\.4\b", title) and not re.search(r"\b6\.4\.\d+\b", title):
            section_level = lvl
          elif section_level <= 2 and re.search(
              r"\b(?:entry\s+points?|privileged|invariants?|handoff\s+targets?)\b",
              title,
              re.IGNORECASE,
          ):
            in_section = False
            section_level = 0
      continue
    if not in_section:
      continue
    if not stripped.startswith("|"):
      if saw_separator:
        table_done = True
      continue
    if table_done:
      continue
    cells = _split_md_row(stripped)
    if header is None:
      header = [c.lower() for c in cells]
      continue
    if all(re.fullmatch(r":?-{3,}:?", c) for c in cells if c):
      saw_separator = True
      continue

    def _col(*names: str, exclude: tuple[str, ...] = ()) -> str:
      for idx, h in enumerate(header or []):
        tokens = set(re.findall(r"[a-z0-9]+", h))
        if tokens & set(exclude):
          continue
        if tokens & set(names) and idx < len(cells):
          return cells[idx]
      return ""

    sup_id = _col("suppression") or _col("id", exclude=("control", "controls", "rule", "rules"))
    glob = _col("glob", "path")
    controls_raw = _col("control", "controls", "rule", "rules", exclude=("suppression",))
    action = _col("action").upper().replace(" ", "_")
    justification = _col("justification", "reason", "rationale")
    sup_id_clean = re.sub(r"[*`]", "", sup_id).strip()
    action_clean = re.sub(r"[*`]", "", action).strip()
    if sup_id_clean.lower() in ("none", "n/a", "na", "-") and action_clean in (
        "",
        "NONE",
        "N/A",
        "NA",
        "-",
    ):
      continue
    if not (sup_id and glob and action in _SUPPRESSION_ACTIONS and justification):
      warnings.append(
          f"Ignored malformed Section 6.4 suppression row (needs ID, Path Glob, "
          f"Action EXCLUDE|VERIFY_MITIGATION, and Justification): {stripped}"
      )
      continue
    controls = frozenset(
        _normalize_suppression_target(c)
        for c in re.split(r"[,\s]+", controls_raw or "*")
        if c.strip().strip("`")
    ) or frozenset({"*"})
    if controls & {"*", "all"}:
      controls = frozenset({"*"})
    rules.append(
        SuppressionRule(
            suppression_id=sup_id,
            path_glob=glob,
            controls=controls,
            action=action,
            justification=justification,
            path_regex=_glob_to_regex(glob),
        )
    )
  return rules, warnings


def _suppression_anchor_dir(input_path: Path, threat_model_path: Path | None) -> Path:
  """Returns the directory that Section 6.4 path globs are relative to.

  Directory scans use the scanned directory. Single-file scans use the closest enclosing
  repository root: the THREAT_MODEL.md directory (when the file is inside it) or the
  nearest ancestor containing `.git`, whichever is deeper, so repository-root globs
  still match.
  """
  if input_path.is_dir():
    return input_path
  candidates: list[Path] = []
  if threat_model_path is not None:
    tm_dir = threat_model_path.resolve().parent
    if input_path.is_relative_to(tm_dir):
      candidates.append(tm_dir)
  git_root = next((a for a in input_path.parents if (a / ".git").exists()), None)
  if git_root is not None:
    candidates.append(git_root)
  if candidates:
    return max(candidates, key=lambda c: len(c.parts))
  return input_path.parent


def _is_default_excluded_test_path(rel_parts: Sequence[str]) -> bool:
  """Returns True for test-harness paths skipped unless `include_tests=True`."""
  if not rel_parts:
    return False
  if any(part in _DEFAULT_EXCLUDED_TEST_DIRS for part in rel_parts[:-1]):
    return True
  return bool(_TEST_FILE_NAME_RE.match(rel_parts[-1]))


def _is_guardrails_self_repo(path: Path) -> bool:
  """Returns True only when `path` is this guardrails repository itself."""
  return (
      path.is_dir()
      and (path / "rules" / "adk-core.yaml").is_file()
      and (path / "scanner" / "scan_agent_codebase.py").is_file()
  )


def _collect_target_files(input_path: Path, include_tests: bool = False) -> list[Path]:
  """Collects Python and config files to scan under `input_path`.

  Test harness paths (`tests/`, `test/`, `__tests__/`, `fixtures/`, `test_*.py`,
  `*_test.py`, `conftest.py`) are skipped unless `include_tests` is True.
  """
  if input_path.is_file():
    return [input_path]

  scan_exts = {".py", ".yaml", ".yml", ".json", ".tf"}
  files: list[Path] = []
  skip_dirs = {
      ".git",
      "__pycache__",
      ".pytest_cache",
      ".venv",
      "venv",
      "node_modules",
      ".tox",
      "build",
      "dist",
  }
  # Skip this repository's own rules/ and scanner/ directories only when scanning
  # the guardrails repository itself (never skip directories in target repos).
  is_repo_root = _is_guardrails_self_repo(input_path)

  for p in sorted(input_path.rglob("*")):
    if not p.is_file() or p.is_symlink():
      continue
    rel_parts = p.relative_to(input_path).parts
    if any(part in skip_dirs or part.startswith(".git") for part in rel_parts):
      continue
    if is_repo_root and rel_parts and (
        rel_parts[0] in ("rules", "scanner")
        or (rel_parts[0] == "tests" and not include_tests)
    ):
      continue
    if not include_tests and _is_default_excluded_test_path(rel_parts):
      continue
    if p.suffix.lower() in scan_exts or p.name == "SKILL.md":
      files.append(p)
  return files


def scan_python_source(
    source_code: str,
    filename: str = "<memory>",
) -> list[dict[str, Any]]:
  """Scans an in-memory Python source string and returns deduplicated findings."""
  tree = ast.parse(source_code, filename=filename)
  visitor = _ScopeAwareSecurityVisitor(rel_path=filename, source_code=source_code)
  visitor.pre_scan(tree)
  visitor.visit(tree)

  results: list[dict[str, Any]] = []
  seen_keys: set[tuple[str, int, str]] = set()
  for control_id, status, lineno, fn_or_agent, desc in visitor.raw_findings:
    dedup_key = (control_id, lineno, desc)
    if dedup_key in seen_keys:
      continue
    seen_keys.add(dedup_key)
    meta = CONTROL_CATALOG[control_id]
    rec_fix = meta.recommended_fix
    results.append({
        "rule_id": meta.rule_id,
        "control_id": control_id,
        "status": status,
        "line": lineno,
        "function_or_agent": fn_or_agent,
        "message": desc,
        "filename": filename,
        "recommended_fix": rec_fix,
        "remediation": rec_fix,
    })
  return results


def scan_codebase(
    input_path: Path,
    threat_model_path: Path | None = None,
    engine: str = "ast",
    packs: Sequence[str] | str | None = None,
    include_tests: bool = False,
) -> dict[str, Any]:
  """Scans `input_path` against all 21 controls and returns summary + findings.

  `packs` opts into optional declarative rule packs (see OPTIONAL_RULE_PACKS), which run
  through Semgrep or Opengrep when one is installed and are skipped otherwise.
  `threat_model_path` links findings to `TM-*` IDs and applies the Section 6.4
  suppression table: `EXCLUDE` rows move findings to `suppressed_findings`, and
  `VERIFY_MITIGATION` rows downgrade them. `include_tests` scans test-harness paths.
  """
  input_path = input_path.resolve()
  base_dir = input_path.parent if input_path.is_file() else input_path
  tm_links = _parse_threat_model_links(threat_model_path)
  suppression_rules, suppression_warnings = _parse_threat_model_suppressions(threat_model_path)
  suppression_anchor = _suppression_anchor_dir(input_path, threat_model_path)

  def _suppression_rel_path(rel_path: str) -> str:
    try:
      return (base_dir / rel_path).resolve().relative_to(suppression_anchor).as_posix()
    except ValueError:
      return rel_path
  target_files = _collect_target_files(input_path, include_tests=include_tests)

  findings: list[SecurityFinding] = []
  suppressed: list[dict[str, Any]] = []
  finding_seq = 1

  normalized_engine = (engine or "ast").strip().lower()
  if normalized_engine not in ("ast", "semgrep", "opengrep", "hybrid"):
    raise ValueError(f"Unsupported engine {engine!r}; expected 'ast', 'semgrep', 'opengrep', or 'hybrid'.")

  external_by_file: dict[str, list[tuple[str, str, int, str, str]]] = {}
  if normalized_engine in ("semgrep", "opengrep", "hybrid"):
    for rel_f, c_id, st, ln, fn_ag, msg in _run_external_grep_engine(
        input_path, engine=normalized_engine, include_tests=include_tests
    ):
      external_by_file.setdefault(rel_f, []).append((c_id, st, ln, fn_ag, msg))
  elif normalized_engine == "ast" and any(
      fp.suffix.lower() != ".py" for fp in target_files
  ):
    if not (
        input_path.is_file()
        and (
            input_path.name in ("adk-core.yaml", ".pre-commit-config.yaml")
            or "cloudbuild" in input_path.name.lower()
        )
    ):
      for rel_f, c_id, st, ln, fn_ag, msg in _run_external_grep_engine(
          input_path,
          engine="hybrid",
          rules_yaml=SEMGREP_RULES_YAML_PATH,
          include_tests=include_tests,
      ):
        if Path(rel_f).suffix.lower() != ".py":
          external_by_file.setdefault(rel_f, []).append((c_id, st, ln, fn_ag, msg))

  def _emit_findings(
      rel_path: str,
      source_lines: list[str],
      raw_items: list[tuple[str, str, int, str, str]],
      finding_seq: int,
  ) -> int:
    seen_keys: set[tuple[str, int, str]] = set()
    for control_id, status, lineno, fn_or_agent, desc in raw_items:
      dedup_key = (control_id, lineno, desc)
      if dedup_key in seen_keys:
        continue
      seen_keys.add(dedup_key)

      meta = CONTROL_CATALOG[control_id]
      matched_tm: list[str] = list(tm_links.get(control_id, []))
      for asi_part in meta.owasp_asi.split("/"):
        for tm_id in tm_links.get(asi_part, []):
          if tm_id not in matched_tm:
            matched_tm.append(tm_id)

      full_desc = desc
      if matched_tm:
        full_desc = f"{desc} (Linked Threat Model IDs: {', '.join(matched_tm)})"

      eff_status = status
      rec_fix = meta.recommended_fix
      engine_rule = fn_or_agent.split(":", 1)[1] if ":" in fn_or_agent else ""
      matched_rule = next(
          (
              r
              for r in suppression_rules
              if r.matches(_suppression_rel_path(rel_path), control_id, meta.rule_id, engine_rule)
          ),
          None,
      )
      if matched_rule is not None and matched_rule.action == "EXCLUDE":
        suppressed.append({
            "control_id": control_id,
            "rule_id": meta.rule_id,
            "severity": meta.severity,
            "file": rel_path,
            "line": lineno,
            "function_or_agent": fn_or_agent,
            "description": desc,
            "suppression_id": matched_rule.suppression_id,
            "path_glob": matched_rule.path_glob,
            "justification": matched_rule.justification,
        })
        continue
      if matched_rule is not None and eff_status == "ACTION_REQUIRED":
        eff_status = "VERIFY_MITIGATION"
        full_desc = (
            f"{full_desc} (Calibrated to VERIFY_MITIGATION by THREAT_MODEL.md "
            f"{matched_rule.suppression_id}: {matched_rule.justification})"
        )

      findings.append(
          SecurityFinding(
              finding_id=f"ASG-{finding_seq:03d}",
              control_id=control_id,
              rule_id=meta.rule_id,
              layer=meta.layer,
              severity=meta.severity,
              owasp_asi=meta.owasp_asi,
              status=eff_status,
              file=rel_path,
              line=lineno,
              function_or_agent=fn_or_agent,
              title=meta.title,
              description=full_desc,
              snippet=_extract_line_snippet(source_lines, lineno),
              security_invariant=meta.security_invariant,
              recommended_fix=rec_fix,
              core_module=meta.core_module,
              threat_model_ids=matched_tm,
              remediation=rec_fix,
          )
      )
      finding_seq += 1
    return finding_seq

  pack_paths = resolve_rule_packs(packs)
  pack_by_file: dict[str, list[tuple[str, str, int, str, str]]] = {}
  pack_engine: str | None = None
  if pack_paths:
    pack_engine = _resolve_grep_binary("opengrep") and "opengrep" or (
        _resolve_grep_binary("semgrep") and "semgrep"
    )
    if pack_engine:
      for rel_f, c_id, st, ln, fn_ag, msg in _run_external_grep_engine(
          input_path,
          engine=pack_engine,
          rules_yaml=pack_paths,
          include_tests=include_tests,
      ):
        pack_by_file.setdefault(rel_f, []).append((c_id, st, ln, fn_ag, msg))

  def _merge_pack_items(
      rel_path: str, raw_items: list[tuple[str, str, int, str, str]]
  ) -> None:
    existing = {(c_id, ln) for c_id, _st, ln, _fn, _d in raw_items}
    for item in pack_by_file.pop(rel_path, []):
      if (item[0], item[2]) not in existing:
        raw_items.append(item)

  scan_units: list[tuple[Path, str]] = [
      (fp, str(fp.relative_to(base_dir))) for fp in target_files
  ]

  for file_path, rel_path in scan_units:
    raw_items: list[tuple[str, str, int, str, str]] = []
    source_lines: list[str] = []

    if file_path.suffix.lower() == ".py":
      try:
        source_code = file_path.read_text(encoding="utf-8")
        source_lines = source_code.splitlines()
        if normalized_engine in ("ast", "hybrid"):
          tree = ast.parse(source_code, filename=rel_path)
          visitor = _ScopeAwareSecurityVisitor(
              rel_path=rel_path, source_code=source_code, file_path=file_path
          )
          visitor.pre_scan(tree)
          visitor.visit(tree)
          raw_items.extend(visitor.raw_findings)
      except (OSError, UnicodeDecodeError, SyntaxError):
        continue
    else:
      try:
        source_lines = file_path.read_text(encoding="utf-8").splitlines()
      except (OSError, UnicodeDecodeError):
        source_lines = []
      raw_items = list(external_by_file.pop(rel_path, []))

    if file_path.suffix.lower() == ".py":
      if normalized_engine in ("semgrep", "opengrep"):
        raw_items = list(external_by_file.pop(rel_path, []))
      elif normalized_engine == "hybrid":
        existing_ctrl_lines = {(c_id, ln) for c_id, _st, ln, _fn, _d in raw_items}
        for ext_item in external_by_file.pop(rel_path, []):
          if (ext_item[0], ext_item[2]) not in existing_ctrl_lines:
            raw_items.append(ext_item)
    _merge_pack_items(rel_path, raw_items)
    finding_seq = _emit_findings(rel_path, source_lines, raw_items, finding_seq)

  # Core and optional-pack findings in files not collected by _collect_target_files
  # (for example Dockerfile, Makefile, deploy.sh, Procfile, or .env files).
  is_repo_root = _is_guardrails_self_repo(input_path)
  skip_leftover_dirs = {
      ".git",
      "__pycache__",
      ".pytest_cache",
      ".venv",
      "venv",
      "node_modules",
      ".tox",
      "build",
      "dist",
  }
  for rel_path in sorted(set(external_by_file) | set(pack_by_file)):
    rel_parts = Path(rel_path).parts
    if any(part in skip_leftover_dirs or part.startswith(".git") for part in rel_parts):
      continue
    if is_repo_root and rel_parts and (
        rel_parts[0] in ("rules", "scanner")
        or (rel_parts[0] == "tests" and not include_tests)
    ):
      continue
    if not include_tests and _is_default_excluded_test_path(rel_parts):
      continue
    leftover_items = list(external_by_file.pop(rel_path, []))
    _merge_pack_items(rel_path, leftover_items)
    try:
      leftover_lines = (base_dir / rel_path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
      leftover_lines = []
    finding_seq = _emit_findings(rel_path, leftover_lines, leftover_items, finding_seq)

  by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
  by_layer: dict[str, int] = {
      f"Layer {i}": 0 for i in range(1, 6)
  }
  action_required_count = 0
  verify_mitigation_count = 0

  for f in findings:
    by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    layer_prefix = f.layer.split(":")[0]
    by_layer[layer_prefix] = by_layer.get(layer_prefix, 0) + 1
    if f.status == "ACTION_REQUIRED":
      action_required_count += 1
    else:
      verify_mitigation_count += 1

  return {
      "summary": {
          "target_path": str(input_path),
          "total_files_scanned": len(target_files),
          "tests_included": include_tests,
          "total_findings": len(findings),
          "action_required_count": action_required_count,
          "verify_mitigation_count": verify_mitigation_count,
          "suppressed_count": len(suppressed),
          "by_severity": by_severity,
          "by_layer": by_layer,
          "threat_model": {
              "path": str(threat_model_path) if threat_model_path else None,
              "suppression_rules": [
                  {
                      "suppression_id": r.suppression_id,
                      "path_glob": r.path_glob,
                      "controls": sorted(r.controls),
                      "action": r.action,
                      "justification": r.justification,
                  }
                  for r in suppression_rules
              ],
              "warnings": suppression_warnings,
          },
          "rule_packs": {
              "requested": [pp.stem.removesuffix("-rules") for pp in pack_paths],
              "engine": pack_engine,
              "intrafile_taint": pack_engine == "opengrep",
              "skipped": bool(pack_paths) and not pack_engine,
          },
      },
      "findings": [asdict(f) for f in findings],
      "suppressed_findings": suppressed,
  }


scan_repository = scan_codebase


def format_markdown_report(report: dict[str, Any]) -> str:
  """Renders a Markdown `SECURITY_AUDIT.md` report."""
  summary = report["summary"]
  findings = report["findings"]
  status_banner = (
      "PASS (0 Action-Required Findings)"
      if summary["action_required_count"] == 0
      else f"ACTION_REQUIRED ({summary['action_required_count']} finding(s) need remediation)"
  )

  lines: list[str] = [
      "# Agent Security Audit Report (`SECURITY_AUDIT.md`)",
      "",
      f"**Status:** `{status_banner}`  ",
      f"**Target Path:** `{summary['target_path']}`  ",
      f"**Files Scanned:** `{summary['total_files_scanned']}`",
      "",
      "## 1. Executive Summary Scorecard",
      "",
      "| Metric | Count |",
      "| :--- | ---: |",
      f"| **Action Required (`ACTION_REQUIRED`)** | `{summary['action_required_count']}` |",
      f"| **Verify Mitigation (`VERIFY_MITIGATION`)** | `{summary['verify_mitigation_count']}` |",
      f"| **CRITICAL Severity** | `{summary['by_severity'].get('CRITICAL', 0)}` |",
      f"| **HIGH Severity** | `{summary['by_severity'].get('HIGH', 0)}` |",
      f"| **MEDIUM Severity** | `{summary['by_severity'].get('MEDIUM', 0)}` |",
      f"| **LOW Severity** | `{summary['by_severity'].get('LOW', 0)}` |",
      f"| **Suppressed by THREAT_MODEL.md Section 6.4** | `{summary.get('suppressed_count', 0)}` |",
      "",
  ]

  suppressed_items = report.get("suppressed_findings") or []
  suppressed_lines: list[str] = []
  if suppressed_items:
    suppressed_lines.extend([
        "## Appendix: Findings Suppressed by THREAT_MODEL.md Section 6.4",
        "",
        "| Suppression ID | Control | Rule ID | Location | Justification |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ])
    for s in suppressed_items:
      suppressed_lines.append(
          f"| `{s['suppression_id']}` | `{s['control_id']}` | `{s['rule_id']}` | "
          f"`{s['file']}:{s['line']}` | {s['justification']} |"
      )
    suppressed_lines.append("")

  if not findings:
    lines.extend([
        "## 2. Findings",
        "",
        "Zero `L1-01`..`L5-04` security violations detected across scanned files.",
        "",
    ])
    lines.extend(suppressed_lines)
    return "\n".join(lines)

  lines.extend([
      "## 2. Findings Overview Table",
      "",
      "| ID | Control | Rule ID | Severity | OWASP | Location | Target | Status |",
      "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
  ])
  for f in findings:
    lines.append(
        f"| `{f['finding_id']}` | `{f['control_id']}` | `{f['rule_id']}` | "
        f"**{f['severity']}** | `{f['owasp_asi']}` | `{f['file']}:{f['line']}` | "
        f"`{f['function_or_agent']}` | `{f['status']}` |"
    )

  lines.extend([
      "",
      "## 3. Detailed Findings & Remediation",
      "",
  ])
  for f in findings:
    lines.extend([
        f"### [{f['finding_id']}] `{f['control_id']}` — {f['title']} (`{f['severity']}`)",
        "",
        f"- **Rule ID:** `{f['rule_id']}`",
        f"- **Layer:** {f['layer']}",
        f"- **OWASP Agentic Top 10:** `{f['owasp_asi']}`",
        f"- **Location:** `{f['file']}:{f['line']}` (in `{f['function_or_agent']}`)",
        f"- **Description:** {f['description']}",
        f"- **Security Invariant:** {f['security_invariant']}",
        f"- **Recommended Fix:** {f['recommended_fix']}",
    ])
    if f.get("snippet"):
      lines.extend([
          "",
          "```python",
          f["snippet"],
          "```",
      ])
    lines.append("")

  lines.extend(suppressed_lines)
  return "\n".join(lines)


def format_sarif_report(report: dict[str, Any]) -> str:
  """Renders a valid SARIF 2.1.0 JSON document from `report`."""
  rules_list: list[dict[str, Any]] = []
  for ctrl_id, meta in CONTROL_CATALOG.items():
    sarif_level = "error" if meta.severity in ("CRITICAL", "HIGH") else "warning"
    rules_list.append({
        "id": meta.rule_id,
        "name": meta.title,
        "shortDescription": {"text": f"[{ctrl_id}] {meta.title}"},
        "fullDescription": {"text": meta.security_invariant},
        "help": {"text": meta.recommended_fix},
        "defaultConfiguration": {"level": sarif_level},
        "properties": {
            "control_id": ctrl_id,
            "layer": meta.layer,
            "severity": meta.severity,
            "owasp_asi": meta.owasp_asi,
            "core_module": meta.core_module,
        },
    })

  results_list: list[dict[str, Any]] = []
  for f in report["findings"]:
    level = "error" if f["severity"] in ("CRITICAL", "HIGH") else "warning"
    results_list.append({
        "ruleId": f["rule_id"],
        "level": level,
        "message": {
            "text": f"[{f['control_id']}] {f['description']} Fix: {f['recommended_fix']}"
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {
                        "startLine": f["line"],
                        "snippet": {"text": f.get("snippet", "")},
                    },
                }
            }
        ],
        "properties": {
            "finding_id": f["finding_id"],
            "control_id": f["control_id"],
            "layer": f["layer"],
            "severity": f["severity"],
            "owasp_asi": f["owasp_asi"],
            "status": f["status"],
            "core_module": f["core_module"],
            "threat_model_ids": f.get("threat_model_ids", []),
        },
    })

  for s in report.get("suppressed_findings") or []:
    level = "error" if s["severity"] in ("CRITICAL", "HIGH") else "warning"
    results_list.append({
        "ruleId": s["rule_id"],
        "level": level,
        "message": {"text": f"[{s['control_id']}] {s['description']}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": s["file"]},
                    "region": {"startLine": s["line"]},
                }
            }
        ],
        "suppressions": [
            {
                "kind": "external",
                "status": "accepted",
                "justification": f"THREAT_MODEL.md {s['suppression_id']}: {s['justification']}",
            }
        ],
        "properties": {
            "control_id": s["control_id"],
            "severity": s["severity"],
            "suppression_id": s["suppression_id"],
        },
    })

  sarif_doc = {
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [
          {
              "tool": {
                  "driver": {
                      "name": "agent-security-audit-scanner",
                      "version": "1.0.0",
                      "informationUri": "https://github.com/mik-sec/agent-security-guardrails",
                      "rules": rules_list,
                  }
              },
              "results": results_list,
          }
      ],
  }
  return json.dumps(sarif_doc, indent=2)


def main(argv: Sequence[str] | None = None) -> int:
  parser = argparse.ArgumentParser(
      description="Scope-aware AST, config, and feature-flag security scanner (L1-01..L5-04)."
  )
  parser.add_argument(
      "--input",
      "--repo",
      "--target-repo",
      "--repo-root",
      dest="input",
      type=Path,
      required=True,
      help="Path to a file or directory to scan.",
  )
  parser.add_argument(
      "--engine",
      choices=("ast", "semgrep", "opengrep", "hybrid"),
      default="ast",
      help="Scanning engine: 'ast' (default scope-aware AST), 'semgrep', 'opengrep', or 'hybrid' (AST + Opengrep/Semgrep merged).",
  )
  parser.add_argument(
      "--packs",
      type=str,
      default=None,
      help=(
          "Comma-separated optional rule packs to add: mcp, gcp-gemini, or all. "
          "Requires opengrep or semgrep; skipped with a warning otherwise."
      ),
  )
  parser.add_argument(
      "--threat-model",
      type=Path,
      default=None,
      help=(
          "Optional path to THREAT_MODEL.md: links findings to TM-* IDs and applies the "
          "Section 6.4 suppression table (EXCLUDE / VERIFY_MITIGATION rows)."
      ),
  )
  parser.add_argument(
      "--include-tests",
      action="store_true",
      help=(
          "Also scan test-harness paths (tests/, test/, __tests__/, fixtures/, test_*.py, "
          "*_test.py, conftest.py), which are skipped by default."
      ),
  )
  parser.add_argument(
      "--format",
      choices=("markdown", "json", "sarif"),
      default="markdown",
      help="Output report format (default: markdown).",
  )
  parser.add_argument(
      "--output",
      "--out",
      dest="output",
      type=Path,
      default=None,
      help="Optional output file path (prints to stdout if omitted).",
  )
  parser.add_argument(
      "--fail-on",
      type=str,
      default=None,
      help="Comma-separated severities (e.g. CRITICAL,HIGH) that trigger exit code 1.",
  )
  args = parser.parse_args(argv)

  if not args.input.exists():
    print(f"Error: input path does not exist: {args.input}", file=sys.stderr)
    return 2
  if args.threat_model is not None and not args.threat_model.is_file():
    print(f"Error: threat model file does not exist: {args.threat_model}", file=sys.stderr)
    return 2

  try:
    report = scan_codebase(
        args.input,
        args.threat_model,
        engine=args.engine,
        packs=[args.packs] if args.packs else None,
        include_tests=args.include_tests,
    )
  except ValueError as exc:
    print(f"Error: {exc}", file=sys.stderr)
    return 2
  for warning in report["summary"]["threat_model"]["warnings"]:
    print(f"Warning: {warning}", file=sys.stderr)
  if report["summary"]["rule_packs"]["skipped"]:
    print(
        "Warning: --packs requested but neither opengrep nor semgrep is installed; "
        "optional rule packs were skipped.",
        file=sys.stderr,
    )

  if args.format == "json":
    rendered = json.dumps(report, indent=2)
  elif args.format == "sarif":
    rendered = format_sarif_report(report)
  else:
    rendered = format_markdown_report(report)

  if args.output is not None:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered + "\n", encoding="utf-8")
  else:
    try:
      print(rendered)
      sys.stdout.flush()
    except BrokenPipeError:
      devnull = os.open(os.devnull, os.O_WRONLY)
      os.dup2(devnull, sys.stdout.fileno())
      return 0

  if args.fail_on:
    fail_severities = {
        s.strip().upper() for s in args.fail_on.split(",") if s.strip()
    }
    matching_failures = [
        f
        for f in report["findings"]
        if f["status"] == "ACTION_REQUIRED" and f["severity"].upper() in fail_severities
    ]
    if matching_failures:
      return 1

  return 0


if __name__ == "__main__":
  if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
  sys.exit(main())
