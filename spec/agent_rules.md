# Agent Rules & Context for Gerion CLI

## 1. User Preferences
- **Language**: Conversation in Spanish, but Code/Comments/Docs in English.
- **Principles**: SOLID, DRY, KISS. Respect existing codebase patterns.
- **Changes**: Only make large architectural changes when strictly justified.
- **Python Style**: Follow PEP 8, type hints on public APIs, Python 3.12+ features when appropriate.
- **Commits**: No "Co-Authored-By". Provide verbose messages explaining *why*, not just *what*.
- **CRITICAL**: If context limit approaches ~95%, STOP immediately and document remaining work in `spec/backlog.md` to avoid data loss.

## 2. Session Start Protocol
- Always read `spec/project_context.md` (architecture) and `spec/backlog.md` (status) to absorb context before starting work.

## 3. Development Workflow
1. **Code Editing**: I allow myself to edit code. I DO NOT run build/test commands automatically. I will notify you when code is ready for verification.
2. **Build/Test**: You (User) are responsible for running `pytest`, `poetry run`, etc., in your terminal. If there are errors, paste the output here for me to analyze.
3. **Git Operations**: You manage Git. I will generate commit messages only when requested, based on `git status` / `git diff`.
4. **Documentation**: I will only update `spec/` files when explicitly requested, in a separate, clean context.
5. **Efficiency**: Minimize tool calls. Do not use `run_command` for build/test/git unless asked. Do not read files unnecessarily.

## 4. Key Files & Architecture

### Entry Points
| File | Purpose |
|------|---------|
| `gerion_cli/main.py` | Typer app, registers all commands |
| `Dockerfile` | Multi-stage Docker build (Trivy + Gitleaks + Semgrep + CLI binary) |
| `pyproject.toml` | Poetry config, version, dependencies |

### Core Layer (`gerion_cli/core/`)
| File | Purpose |
|------|---------|
| `config.py` | `__version__`, `CLIENT_ID` — source of truth for versioning |
| `logging.py` | `GerionLogger` (Rich-based), `LogLevel` and `OutputFormat` enums |
| `metadata.py` | Git metadata + CI/CD env var detection (GitHub, GitLab, Jenkins) |
| `types.py` | `SecretString` wrapper (Pydantic SecretStr + Typer compatibility) |

### Commands Layer (`gerion_cli/commands/`)
| File | Purpose |
|------|---------|
| `secrets_scan.py` | Secrets scan (Gitleaks). Follows standard command pattern. |
| `sca_scan.py` | SCA scan (Trivy fs). Follows standard command pattern. |
| `iac_scan.py` | IaC scan (Trivy config). Follows standard command pattern. |
| `sast_scan.py` | SAST scan (Semgrep). Follows standard command pattern. |
| `report.py` | Report generation. Fetches from API, renders in text/json/md/pdf. |

### Tools Layer (`gerion_cli/tools/`)
| File | Purpose |
|------|---------|
| `secrets.py` | Runs `gitleaks`, returns raw JSON |
| `sca.py` | Runs `trivy fs --scanners vuln`, returns raw JSON |
| `iac.py` | Runs `trivy config`, returns raw JSON |
| `sast.py` | Runs `semgrep scan`, hooks into Premium `StructuralEngine` |
| `parser.py` | Parses all tool outputs to unified Finding dicts. Contains `generate_finding_template()` |

### API Layer (`gerion_cli/api/`)
| File | Purpose |
|------|---------|
| `auth.py` | M2M API key -> JWT token via `POST /api/v1/auth/m2m/authenticate` |
| `client.py` | `send_to_api()` — authenticates then POSTs findings |

### Output Layer (`gerion_cli/output/`)
| File | Purpose |
|------|---------|
| `formats.py` | `save_to_file()` — JSON, Markdown, SARIF writers |
| `tables.py` | `findings_table()` — Rich console table display |

## 5. Coding Conventions

### Command Pattern
All scan commands follow the same pattern (see `spec/project_context.md`). When adding new scan types, replicate this exact pattern.

### Tool Integration Pattern
```python
# 1. Global report path (TODO: migrate to tempfile)
report_path = "gerion-cli-<tool>-report.json"

# 2. Runner function
def run_<tool>_tool(code_path: str) -> List[Dict] | None:
    command = [...]
    try:
        subprocess.run(command, capture_output=True, text=True)
        # Parse JSON from report_path
        return results
    except:
        return [] or None
    finally:
        # Clean up report file
```

### Parser Pattern
```python
def parse_<tool>_tool_output(output, metadata):
    results = []
    seen_ids = set()
    for item in output:
        template = generate_finding_template(metadata)
        finding_id = generate_unique_id([...])
        if finding_id not in seen_ids:
            result = {<tool-specific fields>}
            final = {**template, **result}
            if HAS_PRO: enrich_<tool>_finding(final)
            results.append(final)
            seen_ids.add(finding_id)
    return results
```

### Error Handling
- Use Rich logging functions (`error()`, `warning()`, `success()`) — NOT `print()`.
- `print()` is used in `tools/` layer for simplicity but should migrate to logging.
- API errors: return `None` or `False`, let command layer handle exit.

### Secrets
- Always use `SecretString` wrapper for API keys.
- Never log secret values (SecretString.__str__ returns `***`).
- `hide_input=True` on Typer options for API keys.

### Premium Integration
- Premium features are imported with `try/except ImportError`.
- `HAS_PRO` boolean flag controls conditional execution.
- Core code must ALWAYS work without Premium modules.
- Premium entry points: `gerion_cli/pro/` (not in this repo).

## 6. Environment Variables

| Variable | Purpose | Used In |
|----------|---------|---------|
| `GERION_API_URL` | API Gateway base URL | All scan commands, report |
| `GERION_API_KEY` | M2M API key | All scan commands, report |
| `GERION_CLIENT_ID` | Client identifier (override) | All scan commands, report |
| `GERION_REPO_NAME` | Manual repo name override | metadata.py |
| `GERION_BRANCH_NAME` | Manual branch name override | metadata.py |
| `GERION_COMMIT_HASH` | Manual commit hash override | metadata.py |
| `GERION_BUILD_ID` | Manual build ID override | metadata.py |

## 7. Important Gotchas

1. **No Pydantic models for Findings**: Despite Pydantic being a dependency, findings are raw dicts. This is a known technical debt.
2. **Report command is different**: It fetches from API (requires auth), not from local scans.
3. **Output format inconsistency**: Scan commands use `OutputFormat` enum (json/markdown/sarif), but `report` command uses raw string (text/json/md/pdf). These need unification.
4. **Semgrep severity mapping**: Semgrep uses ERROR/WARNING/INFO, mapped to HIGH/MEDIUM/LOW in `parser.py`.
5. **Finding ID collision risk**: IDs are SHA256 truncated to 12 hex chars. Low collision probability but not UUID-level uniqueness.
6. **CI/CD precedence**: Manual env vars > CI/CD env vars > Git metadata > defaults.
7. **Docker Semgrep**: Semgrep is pip-installed in the Docker image (not a binary), pinned to 1.97.0.

## 8. Testing Strategy (NOT YET IMPLEMENTED)

When implementing tests:
- **Framework**: pytest
- **Mocking**: Mock `subprocess.run` for tool execution, `httpx` for API calls
- **Test data**: Place sample tool outputs in `tests/fixtures/`
- **Categories**: Unit (parsers, metadata), Integration (API auth), E2E (full scan flow with mocks)
- **Coverage target**: Parsers > Commands > API > Output
