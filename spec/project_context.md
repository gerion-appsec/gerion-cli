# Project Context for LLMs

## Identity
**Project**: Gerion CLI v0.1.0 (pyproject.toml)
**Type**: Python CLI Application
**Purpose**: Unified command-line interface for security scanning (SAST, SCA, Secrets, IaC) with API Gateway integration and multi-format output.
**Tests**: 5 test files + 4 JSON fixtures in `tests/`. Covers parsers, metadata, auth, finding template, output formats.

## Architecture Vision

Gerion CLI is a **scanner orchestrator** and **findings normalizer**. It does NOT implement
its own security analysis. It wraps external tools (Gitleaks, OSV-Scanner, KICS, Opengrep),
normalizes their output into a unified Finding model, and dispatches results to the
Gerion API Gateway or local files.

### Responsibility Boundary

| Concern | CLI (this project) | API Gateway (consumer) | Risk Detector (motor) |
|---------|-------------------|----------------------|----------------------|
| Scanner orchestration | Runs tools, collects output | N/A | N/A |
| Output parsing | Normalizes tool JSON to Findings | N/A | N/A |
| Git metadata | Extracts repo/branch/commit | N/A | N/A |
| CI/CD detection | GitHub Actions, GitLab CI, Jenkins | N/A | N/A |
| Authentication | M2M API key -> JWT token | Validates, issues JWT | N/A |
| Findings submission | POST to API Gateway | Stores, deduplicates | N/A |
| Report generation | Fetches from API, renders formats | Serves findings | N/A |
| Output formatting | JSON, Markdown, SARIF, PDF, text | N/A | N/A |
| Reachability analysis | N/A (Premium: delegates to motor) | N/A | BFS traversal, CPG |
| Risk scoring | N/A (Premium: delegates to motor) | N/A | Raw factors |

### Design Principles
- **Tool Agnostic**: Abstract security tool execution behind unified interface
- **Flexible Output**: Support both API submission and local file output
- **CI/CD Ready**: Designed for integration in CI/CD pipelines with environment variable support
- **Docker Native**: Single Docker image with all dependencies
- **Open Core**: Core scanning is open source; Premium features (trace, reachability, risk scoring) are an overlay

### Open Core Architecture
- **Core Image**: Built from `gerion-cli`. Contains SAST, SCA, Secrets, IaC scanning.
- **Premium Image**: Built by overlaying `gerion-cli-premium` on top of Core.
  - Adds **Trace Graphs**, **Deep Reachability Analysis**, **Risk Scoring**.
  - Premium hooks: `gerion_cli/pro/` module (imported conditionally via `try/except ImportError`).
  - Premium detection: `HAS_PRO` flag in `tools/sast.py` and `tools/parser.py`.

## Technical Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Framework | Typer (CLI, built on Click) | ^0.15.2 |
| Python | 3.12+ | |
| HTTP Client | httpx (sync) | ^0.27.0 |
| Terminal UI | Rich (tables, panels, logging) | ^13.7.0 |
| Data Validation | Pydantic (SecretStr only, models are raw dicts) | ^2.6.0 |
| Git Integration | GitPython | ^3.1.44 |
| PDF Generation | fpdf2 | ^2.8.5 |
| Package Manager | Poetry | |
| Build | PyInstaller (single binary) | |

### External Security Tools
| Tool | Purpose | Command Pattern | License |
|------|---------|----------------|---------|
| Gitleaks | Secrets detection | `gitleaks dir <path> --exit-code 0 -f json -r <report>` | MIT |
| Opengrep | SAST (code analysis) | `opengrep scan --config auto --json --output <report> --disable-version-check <path>` | LGPL 2.1 |
| OSV-Scanner | SCA (vuln scanning) | `osv-scanner scan --format json --output <report> -r <path>` | Apache 2.0 |
| KICS | IaC (misconfig scanning) | `kics scan --path <path> --output-path <dir> --report-formats json` | Apache 2.0 |

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
│   │   └── report.py               # Report generation command (fetches from API)
│   ├── core/
│   │   ├── __init__.py             # Exports: SecretString, LogLevel, OutputFormat, logging funcs, get_metadata, CLIENT_ID
│   │   ├── config.py               # __version__, CLIENT_ID
│   │   ├── logging.py              # GerionLogger (Rich-based), LogLevel enum
│   │   ├── metadata.py             # Git metadata extraction + CI/CD env var detection
│   │   └── types.py                # SecretString wrapper, OutputFormat enum
│   ├── output/
│   │   ├── __init__.py             # Exports: save_to_file, findings_table
│   │   ├── formats.py              # JSON, Markdown, SARIF file output
│   │   └── tables.py               # Rich console table display
│   ├── tools/
│   │   ├── __init__.py             # Exports: run_* and parse_* functions for all tools
│   │   ├── secrets.py              # Gitleaks runner
│   │   ├── sca.py                  # OSV-Scanner SCA runner
│   │   ├── iac.py                  # KICS IaC runner
│   │   ├── sast.py                 # Opengrep runner + Premium StructuralEngine hook
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
│   ├── plan.md                     # Technical specification
│   ├── project_context.md          # This document
│   ├── agent_rules.md              # LLM agent development rules
│   ├── backlog.md                  # Development backlog
│   └── tool_output_audit.md        # #9 audit results (no model changes needed)
├── Dockerfile                      # Multi-stage: builder (tools) -> CLI (PyInstaller) -> final (Debian slim)
├── pyproject.toml                  # Poetry config
└── requirements.txt                # Python dependencies (legacy)
```

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
6. Output routing: `save_to_file()` | `send_to_api()` | `findings_table()`

The `scan-all` command runs all 4 scans sequentially through the same `run_scan()`.

The `report` command is different: it authenticates, fetches findings from the API, and renders them
using its own `ReportFormat` enum (text, json, markdown, pdf).

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
| **Premium Fields** | | |
| `trace` | dict | Trace graph (nodes/edges) |
| `reachability` | str | REACHABLE, UNREACHABLE, UNKNOWN |
| `risk_score` | float | Calculated risk score |
| `confidence` | str | LOW, MEDIUM, HIGH |
| `score_breakdown` | dict | Scoring component details |

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

## Authentication Flow

```
CLI (M2M API Key) -> POST /api/v1/auth/m2m/authenticate -> JWT access_token
CLI (JWT Bearer)  -> POST /api/v1/findings -> Submit findings
CLI (JWT Bearer)  -> GET  /api/v1/findings -> Fetch for report
```

## Docker Image

Multi-stage build:
1. **Builder**: Downloads Opengrep, OSV-Scanner, KICS, and Gitleaks binaries, builds CLI with PyInstaller
2. **Final**: Python 3.13 slim + copies binaries
3. Runs as non-root `gerion` user (UID 1000)
4. Volumes: `/code` (scan target), `/output` (results)

## Known Limitations (updated 2026-02-14)

1. **Raw dict models**: Findings use raw dicts (no Pydantic in CLI). Evaluated in #9 —
   validation lives in the API Gateway (`InputFinding`), duplicating models here
   would create a sync burden with no real benefit.
2. **Inconsistent error returns**: `secrets.py` returns `None` on general errors,
   `sca.py`/`iac.py`/`sast.py` return `[]`. The `base.py` handles both cases.

## Key Constraints
- **Python 3.12+**: Required minimum version
- **External tools**: Gitleaks, Opengrep, OSV-Scanner, and KICS must be available in PATH
- **API Gateway**: M2M authentication required for API features
- **Premium overlay**: Pro features loaded conditionally; core must work without them
