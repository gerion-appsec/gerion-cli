# Gerion CLI — Backlog

> Gerion CLI is a **scanner orchestrator** that wraps external security tools,
> normalizes findings, and dispatches results to the Gerion API Gateway.
> Priorities are scoped to: tool integration, output quality, robustness,
> and developer experience.

---

## Strategic Context (post-v0.1.0)

The CLI is **functional but early-stage**. Core scanning (SAST, SCA, Secrets, IaC)
works, API integration is complete, and multiple output formats are supported.
However, the codebase has zero tests, several bugs, significant code duplication,
and the tool choices need revision.

### What's solid
- **4 scan types**: SAST (Semgrep), SCA (Trivy), Secrets (Gitleaks), IaC (Trivy)
- **API integration**: M2M auth + JWT token flow, findings submission
- **Report command**: Fetches from API, renders in text/json/md/pdf
- **CI/CD metadata**: GitHub Actions, GitLab CI, Jenkins + manual overrides
- **Open Core hooks**: Premium enrichment imported conditionally (`HAS_PRO`)
- **Docker image**: Multi-stage build with all tools bundled

### What needs work
- **T1 (Bugs & Stability)**: Fix known bugs, add tool binary checks, add tests
- **T2 (Tool Migration)**: Replace Semgrep with Opengrep, Trivy SCA with OSV-Scanner
- **T3 (Architecture)**: Reduce command duplication, add Pydantic models, unify output formats
- **T4 (Features)**: Scan duration, scan-all command, SARIF import/normalize

### Known limitations
- **No tests**: Zero test coverage. High regression risk.
- **No subprocess timeouts**: Tool hangs will hang the CLI indefinitely.
- **Global report paths**: Race condition risk in parallel execution.
- **Raw dict models**: No validation on findings data structure.

---

## Priority Tiers

| Tier | Goal | Items |
|------|------|-------|
| **T1** | Bugs & Stability — Fix issues | #1, #2, #3 |
| **T2** | Tool Migration — Opengrep + OSV-Scanner | #4, #5, #6 |
| **T3** | Architecture & Quality — DRY, models, tests | #7, #8, #9, #10 |
| **T4** | Features — New capabilities | #11, #12, #13 |

---

## Tier 1 — Bugs & Stability

### #1 Add Tool Binary Availability Checks

**Priority**: HIGH
**Effort**: Low
**Impact**: Clear error messages instead of cryptic subprocess failures

#### Problem
Only `sast.py` checks for tool availability (`shutil.which("semgrep")`).
The other tool runners (`secrets.py`, `sca.py`, `iac.py`) will crash with
unhelpful errors if the binary isn't in PATH.

#### Solution
Add `shutil.which()` check at the start of each `run_*_tool()` function.
Return empty list or None with a clear error message.

#### Files to Modify
- `gerion_cli/tools/secrets.py` — Add `shutil.which("gitleaks")` check
- `gerion_cli/tools/sca.py` — Add `shutil.which("trivy")` check
- `gerion_cli/tools/iac.py` — Add `shutil.which("trivy")` check

---

### #2 Use Tempfile for Report Paths

**Priority**: HIGH
**Effort**: Low
**Impact**: Eliminates race conditions, prevents file leaks in CWD

#### Problem
All tool runners use hardcoded global strings like `report_path = "gerion-cli-sca-report.json"`.
This writes temp files in the current working directory and causes race conditions
if multiple scans run in parallel.

#### Solution
Replace global `report_path` with `tempfile.NamedTemporaryFile(suffix='.json', delete=False)`.
Clean up in the `finally` block (already implemented, just needs tempfile path).

#### Files to Modify
- `gerion_cli/tools/secrets.py`
- `gerion_cli/tools/sca.py`
- `gerion_cli/tools/iac.py`
- `gerion_cli/tools/sast.py`

---

### #3 Add Subprocess Timeouts

**Priority**: HIGH
**Effort**: Low
**Impact**: Prevents CLI from hanging indefinitely on unresponsive tools

#### Problem
All `subprocess.run()` calls have no `timeout` parameter. If a tool hangs
(e.g., Trivy downloading a large DB), the CLI hangs forever.

#### Solution
Add `timeout=300` (5 minutes) to all `subprocess.run()` calls. Catch
`subprocess.TimeoutExpired` and return appropriate error.

#### Files to Modify
- `gerion_cli/tools/secrets.py`
- `gerion_cli/tools/sca.py`
- `gerion_cli/tools/iac.py`
- `gerion_cli/tools/sast.py`

---

## Tier 2 — Tool Migration

### #4 Replace Semgrep with Opengrep (SAST)

**Priority**: HIGH
**Effort**: Medium
**Impact**: Opengrep is the community fork of Semgrep after Semgrep's license change. Fully compatible, open source.

#### Rationale
Semgrep changed its license to a more restrictive model. Opengrep is the
community-driven open-source fork that maintains compatibility with Semgrep
rules and output format. Switching ensures long-term open-source alignment.

#### Solution
1. **CLI**: Replace `semgrep` binary calls with `opengrep` in `tools/sast.py`
2. **Parser**: Verify Opengrep JSON output is compatible with `parse_sast_tool_output()`.
   Opengrep maintains Semgrep output compatibility, so minimal changes expected.
3. **Dockerfile**: Replace `pip install semgrep==1.97.0` with Opengrep binary install.
4. **Tool check**: Update `shutil.which("semgrep")` to `shutil.which("opengrep")`
5. **Documentation**: Update README.md, plan.md references

#### Files to Modify
- `gerion_cli/tools/sast.py` — Change command from `semgrep` to `opengrep`
- `gerion_cli/tools/parser.py` — Verify/adapt SAST output parsing (likely no changes)
- `Dockerfile` — Replace Semgrep install with Opengrep binary
- `README.md` — Update tool references
- `spec/plan.md` — Update tool references

#### Verification
- Run Opengrep on a test codebase, compare JSON output with Semgrep output
- Ensure `parse_sast_tool_output()` produces identical findings

---

### #5 Replace Trivy SCA with OSV-Scanner

**Priority**: HIGH
**Effort**: Medium
**Impact**: OSV-Scanner uses the OSV database (Google's Open Source Vulnerabilities), providing broader coverage and native integration with the Risk Detector motor (which already accepts OSV format).

#### Rationale
1. **OSV format compatibility**: Risk Detector's `mapper.rs` already normalizes
   OSV reports natively. Using OSV-Scanner means the CLI output can feed directly
   into the motor without format conversion.
2. **Broader database**: OSV aggregates from multiple sources (NVD, GitHub Advisory,
   PyPI, npm, Go, etc.).
3. **Simpler SCA-only tool**: Trivy is a multi-purpose tool; OSV-Scanner is focused
   on vulnerability detection.
4. **Keep Trivy for IaC**: Trivy config scanning remains excellent and has no
   equivalent in OSV-Scanner.

#### Solution
1. **CLI**: Replace `trivy fs --scanners vuln` with `osv-scanner scan --format json`
2. **Parser**: Adapt `parse_sca_tool_output()` to handle OSV-Scanner JSON format.
   OSV-Scanner output is structured differently from Trivy (uses OSV schema).
3. **Dockerfile**: Replace Trivy SCA binary with OSV-Scanner binary install.
   Keep Trivy for IaC scanning.
4. **Finding mapping**: Map OSV fields to Finding model:
   - `id` -> `cve` (OSV ID, e.g., `GHSA-xxx` or `CVE-xxx`)
   - `summary` -> `title`
   - `details` -> `description`
   - `affected[].package.name` -> `component_name`
   - `affected[].ranges[].events[].fixed` -> `component_fix`
   - `database_specific.severity` -> `severity`

#### Files to Modify
- `gerion_cli/tools/sca.py` — Replace Trivy command with OSV-Scanner command
- `gerion_cli/tools/parser.py` — Rewrite `parse_sca_tool_output()` for OSV format
- `Dockerfile` — Add OSV-Scanner binary, keep Trivy for IaC only
- `README.md` — Update tool references

#### Verification
- Run OSV-Scanner on a test project, validate findings against Trivy output
- Verify Finding model compatibility with API Gateway

---

### #6 Update Dockerfile for New Tool Stack

**Priority**: HIGH (depends on #4, #5)
**Effort**: Low
**Impact**: Docker image reflects new tool choices

#### Solution
After #4 and #5 are complete:
1. Install Opengrep binary (replace pip install semgrep)
2. Install OSV-Scanner binary (from Google releases)
3. Keep Trivy for IaC scanning only
4. Keep Gitleaks for secrets scanning

#### Files to Modify
- `Dockerfile`

---

## Tier 3 — Architecture & Quality

### #7 Extract Base Scan Command

**Priority**: MEDIUM
**Effort**: Medium
**Impact**: Eliminates ~80% code duplication across 4 scan commands

#### Problem
`secrets_scan.py`, `sca_scan.py`, `iac_scan.py`, and `sast_scan.py` are
nearly identical. They share the same Typer options, the same metadata
collection, the same output logic. Only the tool runner and parser differ.

#### Solution
Create a `commands/base.py` with a `run_scan()` function that accepts:
- `scan_type: str`
- `tool_runner: Callable`
- `output_parser: Callable`
- Standard Typer options

Each command file becomes a thin wrapper that passes its specific runner/parser.

#### Files to Modify
- New: `gerion_cli/commands/base.py`
- `gerion_cli/commands/secrets_scan.py` — Simplify to wrapper
- `gerion_cli/commands/sca_scan.py` — Simplify to wrapper
- `gerion_cli/commands/iac_scan.py` — Simplify to wrapper
- `gerion_cli/commands/sast_scan.py` — Simplify to wrapper

---

### #8 Add Pydantic Models for Findings

**Priority**: MEDIUM
**Effort**: Medium
**Impact**: Runtime validation, better IDE support, clearer data contracts

#### Problem
All findings are raw dicts created by merging `generate_finding_template()`
with tool-specific fields. No validation, no type safety, easy to introduce
typos in field names.

#### Solution
1. Create `core/models.py` with `Finding` and `Metadata` Pydantic models
2. Replace dict creation in parsers with model instantiation
3. Use `.model_dump()` for serialization to API/files

#### Files to Modify
- New: `gerion_cli/core/models.py`
- `gerion_cli/tools/parser.py` — Use Pydantic models instead of dicts
- `gerion_cli/api/client.py` — Serialize models
- `gerion_cli/output/formats.py` — Serialize models

---

### #9 Unify Output Format System

**Priority**: MEDIUM
**Effort**: Low
**Impact**: Consistent format handling across scan commands and report command

#### Problem
Scan commands use `OutputFormat` enum (`json`/`markdown`/`sarif`).
Report command uses raw string (`text`/`json`/`md`/`pdf`).
These need to be unified.

#### Solution
1. Extend `OutputFormat` enum to include `text` and `pdf`
2. Migrate report command to use the enum
3. Add `text` and `pdf` output support to scan commands (optional)

#### Files to Modify
- `gerion_cli/core/logging.py` — Extend `OutputFormat` enum
- `gerion_cli/commands/report.py` — Use `OutputFormat` enum

---

### #10 Add Unit Tests

**Priority**: HIGH
**Effort**: High
**Impact**: Regression safety, confidence for refactoring

#### Problem
Zero test coverage. The `tests/` directory only contains an empty `__init__.py`.

#### Solution
Prioritized test plan:
1. **Parsers** (highest value): Test all `parse_*_tool_output()` with fixture data
2. **Metadata**: Test `get_metadata()` with mocked git repos and env vars
3. **Finding template**: Test `generate_finding_template()`, `generate_unique_id()`
4. **API auth**: Test `authenticate_with_api()` with mocked httpx responses
5. **Output formats**: Test JSON, Markdown, SARIF serialization

#### Files to Create
- `tests/fixtures/` — Sample tool JSON outputs
- `tests/test_parser.py`
- `tests/test_metadata.py`
- `tests/test_auth.py`
- `tests/test_output.py`

---

## Tier 4 — Features

### #11 Add Scan Duration Tracking

**Priority**: LOW
**Effort**: Low
**Impact**: Frontend needs this field to display scan duration

#### Problem
From TODO file: "En el front, en el apartado scans hay un campo duración del scan
que no se puede mostrar porque no lo capturamos con la cli."

#### Solution
1. Record `start_time` before tool execution
2. Calculate `duration_seconds` after tool completes
3. Add `scan_duration` field to metadata
4. Include in API submission

#### Files to Modify
- `gerion_cli/commands/*.py` — Add timing around tool execution
- `gerion_cli/core/metadata.py` — Or add to the metadata dict

---

### #12 Add `scan-all` Command

**Priority**: LOW
**Effort**: Low (after #7)
**Impact**: Single command to run all scan types

#### Problem
Users must run 4 separate commands for a full scan. A unified command
would improve CI/CD integration and UX.

#### Solution
Add a `scan-all` command that runs secrets, SCA, IaC, and SAST scans
sequentially and aggregates results.

#### Files to Modify
- New: `gerion_cli/commands/scan_all.py`
- `gerion_cli/main.py` — Register new command

---

### #13 Migrate Tool Runners to Use Logging

**Priority**: LOW
**Effort**: Low
**Impact**: Consistent log output from tool layer

#### Problem
Tool runners (`tools/*.py`) use `print()` for error messages instead of
the Rich logging functions (`error()`, `warning()`) used everywhere else.

#### Solution
Replace `print()` calls with proper logging calls in all tool runners.

#### Files to Modify
- `gerion_cli/tools/secrets.py`
- `gerion_cli/tools/sca.py`
- `gerion_cli/tools/iac.py`
- `gerion_cli/tools/sast.py`

---

## Out of Scope (Other Projects' Responsibility)

These are NOT backlog items for the CLI:
- **Reachability analysis** — Risk Detector motor
- **CPG construction** — Risk Detector motor
- **Risk score calculation from raw factors** — Risk Detector motor
- **API Gateway schema changes** — API Gateway project
- **Frontend display** — Frontend project
- **Framework rule files** — Data enrichment project

---

## Completed

| # | Item | Version | Notes |
|---|------|---------|-------|
| — | Initial CLI scaffold | v0.1.0 | Typer app, 4 scan commands, API integration |
| — | Secrets scanning (Gitleaks) | v0.1.0 | Tool runner + parser |
| — | SCA scanning (Trivy) | v0.1.0 | Tool runner + parser |
| — | IaC scanning (Trivy config) | v0.1.0 | Tool runner + parser |
| — | SAST scanning (Semgrep) | v0.1.0 | Tool runner + parser + Premium hook |
| — | M2M API authentication | v0.1.0 | API key -> JWT flow |
| — | Multi-format output | v0.1.0 | JSON, Markdown, SARIF |
| — | Report command | v0.1.0 | Fetches from API, renders text/json/md/pdf |
| — | CI/CD metadata detection | v0.1.0 | GitHub Actions, GitLab CI, Jenkins |
| — | Docker multi-stage build | v0.1.0 | Trivy + Gitleaks + Semgrep + CLI binary |
| — | Premium Open Core hooks | v0.1.0 | Conditional import of `gerion_cli/pro/` |
