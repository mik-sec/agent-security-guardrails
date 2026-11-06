# Agent Security Guardrails

Static security checks for AI agents built with the
[Agent Development Kit (ADK)](https://github.com/google/adk-python), packaged as
a GitHub Actions workflow that other repositories can run on every pull request.

The scanner combines two engines:

- **AST checks** (Python `ast`): scope-aware checks that follow variables and
  function scope. Examples: tool functions that take `user_id` or credentials
  from the model, state-changing tools without human confirmation, instructions
  built from session state, runners without input/output screening.
- **[Opengrep](https://github.com/opengrep/opengrep) rules**: declarative
  patterns, including taint rules and YAML/JSON configs such as MCP server
  files.

Findings map to 21 controls (`L1-01` to `L5-04`) in five layers: prompt and
model integrity, identity and auth, tools and connectors, multi-agent and
sandbox isolation, and telemetry and delivery.

## Repository layout

```text
.github/workflows/agent-security-scan.yml   Workflow other repositories run
scanner/scan_agent_codebase.py              Scanner (AST + Opengrep), Python 3.10+
rules/adk-core.yaml                         ADK rules (39) and the control catalog
rules/mcp.yaml                              MCP client/server rules (15)
rules/gcp-gemini.yaml                       Google Cloud and Gemini SDK rules (15)
```

## Add the scan to a repository

Add this file as `.github/workflows/agent-security.yml` in each repository you
want to scan:

```yaml
name: Agent Security

on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  agent-security:
    uses: mik-sec/agent-security-guardrails/.github/workflows/agent-security-scan.yml@main
    with:
      enforce: false # true fails the check on CRITICAL/HIGH findings
```

Every pull request then gets:

| Output | Where it appears |
| --- | --- |
| Inline annotations | **Files changed** tab, on the flagged lines (up to 10 errors and 10 warnings per run) |
| Review comments | **Conversation** tab, on lines the pull request changed |
| Summary comment | One comment per pull request, updated on each push. Says **LGTM** when the scan is clean |
| Job summary | Full findings table on the workflow run page |
| SARIF report | `agent-security-sarif` artifact on the workflow run |

Inputs:

| Input | Default | Meaning |
| --- | --- | --- |
| `enforce` | `false` | Fail the check when findings at `fail_on` severities exist |
| `fail_on` | `CRITICAL,HIGH` | Severities that fail the check when `enforce` is on |
| `packs` | `all` | Rule packs added to `adk-core`: `mcp`, `gcp-gemini`, `all`, or empty |
| `runs_on` | `ubuntu-latest` | Runner label, for example `self-hosted` |

## Block merges on CRITICAL and HIGH findings

1. Set `enforce: true` in the caller workflow. The check now fails when the
   scan finds CRITICAL or HIGH issues.
2. Make the check required so a failing scan blocks the merge button: in the
   target repository go to **Settings → Rules → Rulesets → New branch ruleset**,
   target the default branch, enable **Require status checks to pass**, and add
   the check `agent-security / Agent security scan`.

To switch back to advisory mode, set `enforce: false`. The comments and
annotations keep working; only the failing check goes away.

On GitHub Enterprise, organization and enterprise rulesets can also require a
workflow directly (**Require workflows to pass before merging**), so target
repositories need no caller file. For an organization ruleset, the workflow must
live in a repository in that organization; to cover several organizations, use
an enterprise ruleset. This workflow runs unchanged in that mode. Set the
Actions variable `AGENT_SECURITY_ENFORCE` to `true` in the target organization
to block merges.

## Email on failure

GitHub notifies the person who triggered a workflow run when it finishes. To
get an email only when the scan fails, open **Settings → Notifications →
System → Actions**, choose **Email**, and select **Only notify for failed
workflows**. With `enforce: false` the run never fails, so no failure email is
sent; the pull request comment still lists the findings.

## Run the scanner locally

```bash
# Requires Python 3.10+. Opengrep is optional; without it only AST checks run.
python3 scanner/scan_agent_codebase.py --input path/to/agent-repo \
  --engine hybrid --packs all --format markdown

# Fail (exit code 1) on CRITICAL or HIGH findings:
python3 scanner/scan_agent_codebase.py --input path/to/agent-repo \
  --engine hybrid --packs all --fail-on CRITICAL,HIGH
```

Formats: `markdown`, `json`, `sarif`. Test files (`tests/`, `test_*.py`,
`conftest.py`) are skipped unless you pass `--include-tests`.

## Suppress a finding

Add a table to `THREAT_MODEL.md` in the target repository, under a heading that
contains `6.4` or `False-Positive Suppression`:

```markdown
## 6.4 False-Positive Suppression Rules

| Suppression ID | Path Glob | Controls | Action | Justification |
| --- | --- | --- | --- | --- |
| SUP-01 | demos/** | * | EXCLUDE | Intentionally vulnerable training samples |
| SUP-02 | app/agent.py | L1-03 | VERIFY_MITIGATION | Screening runs in the API gateway |
```

`EXCLUDE` hides matching findings. `VERIFY_MITIGATION` keeps them in the report
but stops them from failing the check. The workflow reads `THREAT_MODEL.md`
from the pull request's base branch, so a pull request cannot suppress its own
findings.

## Scope and limits

- Built for ADK agents in Python, MCP configuration files, and Google Cloud /
  Gemini SDK usage.
- It does not replace a general SAST, secrets, or dependency scanner. Generic
  bugs such as SQL injection or committed secrets are out of scope.
- Static checks report risky patterns, not proven exploits. Review each finding
  before acting on it.

## License

[Apache License 2.0](LICENSE)
