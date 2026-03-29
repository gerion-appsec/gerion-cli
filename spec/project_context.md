# Project Context for LLMs

## Identity

**Project**: Gerion CLI v1.0.0 (`pyproject.toml`)
**Type**: Python CLI Application
**Purpose**: Unified command-line interface for security scanning (SAST, SCA, Secrets, IaC) with API Gateway integration and multi-format output.
**Tests**: 5 test files + 4 JSON fixtures in `tests/`. Covers parsers, metadata, auth, finding template, output formats.

---

## Architecture Vision

Gerion CLI is a **scanner orchestrator** and **findings normalizer**. It does NOT implement
its own security analysis. It wraps external tools (Gitleaks, OSV-Scanner, KICS, Opengrep),
normalizes their output into a unified Finding model, and dispatches results to the
Gerion API Gateway or local files.

### Responsibility Boundary

| Concern | CLI (this project) | API Gateway (consumer) |
|---------|-------------------|----------------------|
| Scanner orchestration | Runs tools, collects output | N/A |
| Output parsing | Normalizes tool JSON to Findings | N/A |
| Git metadata | Extracts repo/branch/commit | N/A |
| CI/CD detection | GitHub Actions, GitLab CI, Jenkins | N/A |
| Authentication | M2M API key -> JWT token | Validates, issues JWT |
| Findings submission | POST to API Gateway | Stores, deduplicates |
| Report generation | Fetches from API, renders formats | Serves findings |
| Output formatting | JSON, Markdown, SARIF, PDF, text | N/A |

### Design Principles

- **Tool Agnostic**: Abstract security tool execution behind unified interface
- **Flexible Output**: Support both API submission and local file output
- **CI/CD Ready**: Designed for integration in CI/CD pipelines with environment variable support
- **Docker Native**: Single Docker image with all dependencies

---

## Technical Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Framework | Typer (CLI, built on Click) | ^0.24.0 |
| Python | 3.12+ | |
| HTTP Client | httpx (sync) | ^0.28.0 |
| Terminal UI | Rich (tables, panels, logging) | ^14.0.0 |
| Data Validation | Pydantic (SecretStr only, models are raw dicts) | ^2.6.0 |
| Git Integration | GitPython | ^3.1.44 |
| PDF Generation | fpdf2 | ^2.8.5 |
| Package Manager | Poetry | |

### External Security Tools

| Tool | Version | Purpose | Command Pattern | License |
|------|---------|---------|----------------|---------|
| Gitleaks | 8.30.1 | Secrets detection | `gitleaks dir <path> --exit-code 0 -f json -r <report>` | MIT |
| Opengrep | 1.16.5 | SAST (code analysis) | `opengrep scan --config auto --json --output <report> --disable-version-check <path>` | LGPL 2.1 |
| OSV-Scanner | 2.3.5 | SCA (vuln scanning) | `osv-scanner scan --format json --output <report> -r <path>` | Apache 2.0 |
| KICS | 2.1.20 | IaC (misconfig scanning) | `kics scan --path <path> --output-path <dir> --report-formats json` | Apache 2.0 |

### Tool Selection Rationale

- **Opengrep over Semgrep**: Community fork after Semgrep's Dec 2024 license change. Same rules, same output format. Backed by Endor Labs, Aikido, Orca, Jit. LGPL 2.1. Install via binary only (PyPI package was hijacked).
- **OSV-Scanner over Trivy SCA**: Native OSV format output. Broader DB (aggregates NVD, GitHub Advisory, PyPI, npm, Go). Focused SCA-only tool.
- **KICS over Checkov/Trivy IaC**: Go binary (no Python bloat in Docker image), 2400+ queries, supports 15+ IaC formats (Terraform, K8s, Dockerfile, CloudFormation, Helm, Ansible, OpenAPI, Pulumi). Apache 2.0.
- **Gitleaks over TruffleHog**: TruffleHog rejected due to AGPL-3.0 risk for an Apache 2.0 project (subprocess invocation as derivative work is legally gray). detect-secrets (Yelp) rejected as essentially unmaintained.

---

## Source Tree

```
gerion-cli/
├── gerion_cli/
│   ├── __init__.py                 # Package init (empty)
│   ├── main.py                     # Typer app entry point, registers all commands
│   ├── api/
│   │   ├── __init__.py             # Exports: send_to_api, authenticate_with_api
│   │   ├── auth.py                 # M2M API key -> JWT authentication
│   │   └── client.py               # HTTP client for findings submission
│   ├── commands/
│   │   ├── __init__.py             # Exports all command functions
│   │   ├── base.py                 # Shared scan orchestration (run_scan + duration tracking)
│   │   ├── secrets_scan.py         # Secrets scan command (Gitleaks) — thin wrapper
│   │   ├── sca_scan.py             # SCA scan command (OSV-Scanner) — thin wrapper
│   │   ├── iac_scan.py             # IaC scan command (KICS) — thin wrapper
│   │   ├── sast_scan.py            # SAST scan command (Opengrep) — thin wrapper
│   │   ├── scan_all.py             # Runs all 4 scans sequentially
│   │   └── report.py               # Report generation command (fetches from API, --output-file, Rich logging)
│   ├── core/
│   │   ├── __init__.py             # Exports: SecretString, LogLevel, OutputFormat, logging funcs, get_metadata, CLIENT_ID
│   │   ├── config.py               # __version__, CLIENT_ID
│   │   ├── logging.py              # GerionLogger (Rich-based, stderr), LogLevel enum
│   │   ├── metadata.py             # Git metadata extraction + CI/CD env var detection
│   │   └── types.py                # SecretString wrapper, OutputFormat enum (json, markdown, sarif, table)
│   ├── output/
│   │   ├── __init__.py             # Exports: save_to_file, print_formatted, findings_table
│   │   ├── formats.py              # JSON, Markdown, SARIF file/stdout output + content generators
│   │   └── tables.py               # Rich console table display (own stdout Console)
│   ├── tools/
│   │   ├── __init__.py             # Exports: run_* and parse_* functions for all tools
│   │   ├── secrets.py              # Gitleaks runner
│   │   ├── sca.py                  # OSV-Scanner SCA runner
│   │   ├── iac.py                  # KICS IaC runner
│   │   ├── sast.py                 # Opengrep runner
│   │   └── parser.py               # Output parsers for all tools + finding template
│   └── utils/
│       └── __init__.py             # Empty
├── tests/
│   ├── conftest.py                 # Shared fixtures (mock_metadata, load_fixture)
│   ├── fixtures/                   # Tool JSON output samples
│   │   ├── gitleaks.json
│   │   ├── osv.json
│   │   ├── opengrep.json
│   │   └── kics.json
│   ├── test_parser.py              # Parser tests for all 4 tools
│   ├── test_metadata.py            # Git/CI metadata extraction tests
│   ├── test_finding.py             # Finding template + unique ID + redact tests
│   ├── test_auth.py                # M2M API authentication tests
│   └── test_output.py              # JSON/Markdown/SARIF output tests
├── spec/
│   ├── project_context.md          # This document
│   └── agent_rules.md              # LLM agent development rules
├── Dockerfile                      # Multi-stage: tool-builder + kics-builder + final (python:3.13-slim)
├── Makefile                        # Install/uninstall targets for Python deps and scanner binaries
└── pyproject.toml                  # Poetry config
```

---

## Command Pattern

All scan commands are thin wrappers that call `commands/base.py:run_scan()`:

```python
# Each command file (e.g. secrets_scan.py) only defines Typer options and calls:
run_scan(
    scan_type="Secrets",
    tool_name="Gitleaks",
    tool_runner=run_secrets_tool,
    tool_parser=parse_secrets_tool_output,
    # ...standard Typer options forwarded...
)
```

`run_scan()` handles the full orchestration flow:
1. `set_log_level()` + `SecretString.from_typer_option()`
2. `get_metadata()` + `metadata['scan_type'] = scan_type`
3. `tool_runner()` with `time.time()` duration tracking → `metadata['scan_duration']`
4. `tool_parser()` → `results = {'metadata': metadata, 'findings': findings}`
5. `panel()` summary (repo, branch, commit, findings count, duration)
6. Output routing (mutually exclusive priority chain):
   `--output-file` → `save_to_file()` |
   `--format` → `print_formatted()` (stdout) |
   API creds → `send_to_api()` |
   fallback → `findings_table()` (stdout)

The `scan-all` command runs all 4 scans sequentially through the same `run_scan()`.
When `--output-file` or `--format` is set, individual scans are suppressed and `scan_all`
handles aggregated output at the end using the same priority chain.

The `report` command is different: it authenticates, fetches findings from the API, and renders them
using its own `ReportFormat` enum (text, json, markdown, pdf). Uses `--output-file` (unified with
scan commands) and requires `--api-url` (no hardcoded default).

---

## Data Models

### Finding (raw dict, NOT Pydantic)

All findings share this template from `parser.py:generate_finding_template()`:

| Field | Type | Source |
|-------|------|--------|
| `finding_id` | str | SHA256 hash (truncated 12 chars) of tool-specific key fields |
| `title` | str | Tool-specific |
| `description` | str | Tool-specific |
| `mitigation` | str | Tool-specific |
| `severity` | str | Critical, High, Medium, Low, Info |
| `security_scope` | str | Code, IaC |
| `scan_type` | str | Secrets, SCA, IaC, SAST |
| `repository_name` | str | From git metadata |
| `branch_name` | str | From git metadata |
| `build_id` | str | From CI/CD env vars |
| `code_path` | str | User-provided scan path |
| `commit_hash` | str | From git metadata |
| `commit_author` | str | From git metadata |
| `file_path` | str | File where finding was detected |
| `line_number` | int | Line number in file |
| `component_name` | str | (SCA) Package name |
| `component_version` | str | (SCA) Package version |
| `component_fix` | str | (SCA) Fixed version |
| `cwe` | list[str] | CWE identifiers |
| `cve` | str | (SCA) CVE identifier |
| `active` | bool | Always True at creation |
| `mitigated` | bool | Always False at creation |
| `false_positive` | bool | Always False at creation |
| `creation_date` | str | ISO timestamp |
| `last_update_date` | str | ISO timestamp |

### Metadata (raw dict)

| Field | Type | Priority |
|-------|------|----------|
| `repository_name` | str | GERION_REPO_NAME > CI/CD > git remote > "local" |
| `branch_name` | str | GERION_BRANCH_NAME > CI/CD > git active branch > "local" |
| `build_id` | str | GERION_BUILD_ID > CI/CD > "0" |
| `code_path` | str | User argument > CI/CD workspace > cwd |
| `commit_hash` | str | GERION_COMMIT_HASH > CI/CD > git HEAD |
| `commit_author` | str | CI/CD > git commit author |
| `scan_type` | str | Set by command handler |
| `scan_duration` | float | Seconds elapsed during tool execution (set by `base.py`) |

---

## Authentication Flow

```
CLI (M2M API Key) -> POST /api/v1/auth/m2m/authenticate -> JWT access_token
CLI (JWT Bearer)  -> POST /api/v1/findings               -> Submit findings
CLI (JWT Bearer)  -> GET  /api/v1/findings               -> Fetch for report
```

---

## Docker Image

Three-stage build (`python:3.13-slim-bookworm` base for all stages except kics-builder):

1. **tool-builder**: Downloads Gitleaks, Opengrep, and OSV-Scanner binaries into `/usr/local/bin/`
2. **kics-builder** (`golang:1.23`): Clones KICS at the pinned version tag, builds with `go build -ldflags="-s -w"`, compresses with UPX
3. **final**: Copies all binaries from the two builder stages, installs the `gerion` CLI via Poetry/PyInstaller; runs as non-root `gerion` user (UID 1000); entrypoint is `gerion`; default CMD is `--help`

Volumes: `/code` (scan target), `/output` (results).
KICS built-in queries are used (empty `/usr/local/bin/assets/queries` dir is required for KICS startup but the binary falls back to internal rules when empty).

---

## Known Limitations

1. **Raw dict models**: Findings use raw dicts (no Pydantic in CLI). Validation lives in the API Gateway (`InputFinding`); duplicating models here would create a sync burden with no real benefit.
2. **Inconsistent error returns**: `secrets.py` returns `None` on general errors; `sca.py`/`iac.py`/`sast.py` return `[]`. `base.py` handles both cases.
3. **`--log-level` per-command only**: Not promoted to a global callback. Minor UX inconvenience, low priority.

## Key Constraints

- **Python 3.12+**: Required minimum version
- **External tools**: Gitleaks, Opengrep, OSV-Scanner, and KICS must be available in PATH
- **API Gateway**: M2M authentication required for API features
