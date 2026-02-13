# Project Context for LLMs

## Identity
**Project**: Gerion CLI v0.1.0 (pyproject.toml)
**Type**: Python CLI Application
**Purpose**: Unified command-line interface for security scanning (SAST, SCA, Secrets, IaC) with API Gateway integration and multi-format output.
**Tests**: 0 test files. Only `tests/__init__.py` exists (empty).

## Architecture Vision

Gerion CLI is a **scanner orchestrator** and **findings normalizer**. It does NOT implement
its own security analysis. It wraps external tools (Gitleaks, Trivy, Semgrep/Opengrep),
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
| Tool | Purpose | Command Pattern |
|------|---------|----------------|
| Gitleaks | Secrets detection | `gitleaks dir <path> --exit-code 0 -f json -r <report>` |
| Trivy | SCA (vuln scanning) | `trivy fs --scanners vuln -f json --exit-code 0 -o <report> <path>` |
| Trivy | IaC (misconfig scanning) | `trivy config -f json -o <report> <path>` |
| Semgrep | SAST (code analysis) | `semgrep scan --config auto --json --output <report> <path>` |

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
│   │   ├── __init__.py             # Empty
│   │   ├── secrets_scan.py         # Secrets scan command (Gitleaks)
│   │   ├── sca_scan.py             # SCA scan command (Trivy fs)
│   │   ├── iac_scan.py             # IaC scan command (Trivy config)
│   │   ├── sast_scan.py            # SAST scan command (Semgrep)
│   │   └── report.py               # Report generation command (fetches from API)
│   ├── core/
│   │   ├── __init__.py             # Exports: SecretString, LogLevel, OutputFormat, logging funcs, get_metadata, CLIENT_ID
│   │   ├── config.py               # __version__, CLIENT_ID
│   │   ├── logging.py              # GerionLogger (Rich-based), LogLevel, OutputFormat enums
│   │   ├── metadata.py             # Git metadata extraction + CI/CD env var detection
│   │   └── types.py                # SecretString wrapper (Pydantic SecretStr + Typer compat)
│   ├── output/
│   │   ├── __init__.py             # Exports: save_to_file, findings_table
│   │   ├── formats.py              # JSON, Markdown, SARIF file output
│   │   └── tables.py               # Rich console table display
│   ├── tools/
│   │   ├── __init__.py             # Exports: run_* and parse_* functions for all tools
│   │   ├── secrets.py              # Gitleaks runner
│   │   ├── sca.py                  # Trivy SCA runner
│   │   ├── iac.py                  # Trivy IaC runner
│   │   ├── sast.py                 # Semgrep runner + Premium StructuralEngine hook
│   │   └── parser.py               # Output parsers for all tools + finding template
│   └── utils/
│       └── __init__.py             # Empty
├── tests/
│   └── __init__.py                 # Empty (NO tests exist)
├── spec/
│   ├── plan.md                     # Technical specification
│   ├── project_context.md          # This document
│   ├── agent_rules.md              # LLM agent development rules
│   └── backlog.md                  # Development backlog
├── Dockerfile                      # Multi-stage: builder (Trivy+Gitleaks) -> CLI (PyInstaller) -> final (Alpine)
├── pyproject.toml                  # Poetry config
└── requirements.txt                # Python dependencies (legacy)
```

## Command Pattern

All scan commands (`secrets_scan`, `sca_scan`, `iac_scan`, `sast_scan`) follow the same flow:

```
1. set_log_level(log_level)
2. api_key_string = SecretString.from_typer_option(api_key)
3. metadata = get_metadata(code_path)
4. metadata['scan_type'] = '<TYPE>'
5. tool_output = run_<tool>_tool(code_path)
6. results = {'metadata': metadata, 'findings': parse_<tool>_tool_output(tool_output, metadata)}
7. panel(summary)
8. if output_file: save_to_file(results, output_file, format)
   else: send_to_api(results, ...) or findings_table(results['findings'], '<TYPE>')
```

The `report` command is different: it authenticates, fetches findings from the API, and renders them.

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

## Authentication Flow

```
CLI (M2M API Key) -> POST /api/v1/auth/m2m/authenticate -> JWT access_token
CLI (JWT Bearer)  -> POST /api/v1/findings -> Submit findings
CLI (JWT Bearer)  -> GET  /api/v1/findings -> Fetch for report
```

## Docker Image

Multi-stage build:
1. **Builder**: Downloads Trivy + Gitleaks binaries, builds CLI with PyInstaller
2. **Final**: Python 3.13 slim + `pip install semgrep==1.97.0` + copies binaries
3. Runs as non-root `gerion` user (UID 1000)
4. Volumes: `/code` (scan target), `/output` (results)

## Known Issues (as of code review 2026-02-13)

1. **`parser.py:270-274`**: `enrich_sast_finding()` is called TWICE (duplicate block)
2. **`parser.py:280-281`**: Unreachable `return results` after first return at line 278
3. **Global report paths**: All tool runners use hardcoded global `report_path` strings instead of `tempfile`, causing race conditions in parallel execution
4. **Missing tool checks**: `secrets.py`, `sca.py`, `iac.py` don't verify tool binary exists (only `sast.py` checks `shutil.which`)
5. **No subprocess timeouts**: All `subprocess.run()` calls have no timeout, could hang indefinitely
6. **No Pydantic models**: Despite Pydantic being a dependency, findings use raw dicts with no validation
7. **No tests**: Zero test files exist
8. **Massive command duplication**: All 4 scan commands are near-identical boilerplate
9. **Inconsistent error returns**: `secrets.py` returns `None` on error, `sca.py`/`iac.py` return `[]`

## Key Constraints
- **Python 3.12+**: Required minimum version
- **External tools**: Gitleaks, Trivy, and Semgrep must be available in PATH
- **API Gateway**: M2M authentication required for API features
- **Premium overlay**: Pro features loaded conditionally; core must work without them
