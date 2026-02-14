# Gerion CLI — Backlog

> Gerion CLI is a **scanner orchestrator** that wraps external security tools,
> normalizes findings, and dispatches results to the Gerion API Gateway.
> Priorities are scoped to: tool integration, output quality, robustness,
> and developer experience.

---

## Strategic Context (post-v0.1.0)

The CLI is **functional but early-stage**. Core scanning (SAST, SCA, Secrets, IaC)
works, API integration is complete, and multiple output formats are supported.
T1 stability fixes and T2 tool migrations are done (including Dockerfile).
Next priority: T3 architecture and quality improvements.

### Tool stack
| Category | Tool | License | Install | Status |
|----------|------|---------|---------|--------|
| SAST | **Opengrep** | LGPL 2.1 | Binary (Nuitka self-contained) | **Active** |
| SCA | **OSV-Scanner** | Apache 2.0 | Go binary | **Active** |
| IaC | **KICS** | Apache 2.0 | Go binary | **Active** |
| Secrets | **Gitleaks** | MIT | Go binary | **Active** |

> All binaries. All permissive licenses. Trivy and Semgrep eliminated completely.

### Tool selection rationale
- **Opengrep over Semgrep**: Community fork after Semgrep's Dec 2024 license change.
  Same rules, same output format. Backed by Endor Labs, Aikido, Orca, Jit.
  LGPL 2.1. Install via binary only (PyPI package was hijacked).
- **OSV-Scanner over Trivy SCA**: Native OSV format output — Risk Detector's
  `mapper.rs` already consumes OSV natively. Broader DB (aggregates NVD, GitHub
  Advisory, PyPI, npm, Go). Focused SCA-only tool.
- **KICS over Checkov/Trivy IaC**: Go binary (no Python bloat in Docker image),
  2400+ queries (vs Checkov's 1000+ or Trivy's ~500), supports 15+ IaC formats
  (Terraform, K8s, Dockerfile, CF, Helm, Ansible, OpenAPI, Pulumi...), Apache 2.0.
- **Gitleaks kept**: MIT license, fast, mature, actively maintained. TruffleHog
  rejected due to AGPL-3.0 risk for Apache 2.0 Open Core project (subprocess
  invocation as derivative work is legally gray). detect-secrets (Yelp) rejected
  as essentially unmaintained.

### Known limitations
- **No tests**: Zero test coverage. High regression risk.
- **Raw dict models**: Findings use raw dicts (no Pydantic). Evaluated in #9 —
  validation lives in the API Gateway (`InputFinding`), duplicating models here
  would create a sync burden with no real benefit.

---

## Priority Tiers

| Tier | Goal | Items |
|------|------|-------|
| **T1** | Bugs & Stability | ~~#1, #2, #3~~ DONE |
| **T2** | Tool Migration — Opengrep + OSV-Scanner + KICS | ~~#4, #5, #6, #7~~ DONE |
| **T3** | Architecture & Quality — DRY, models, tests | ~~#8, #9~~, #10, #11 |
| **T4** | Features — New capabilities | #12, #13, #14 |

---

## Tier 3 — Architecture & Quality

---

---

### #10 Unify Output Format System

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

### #11 Add Unit Tests

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

### #12 Add Scan Duration Tracking

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

### #13 Add `scan-all` Command

**Priority**: LOW
**Effort**: Low (after #8)
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

### #14 Migrate Tool Runners to Use Logging

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

| # | Item | Notes |
|---|------|-------|
| — | Initial CLI scaffold | Typer app, 4 scan commands, API integration |
| — | Secrets scanning (Gitleaks) | Tool runner + parser |
| — | SCA scanning | Tool runner + parser |
| — | IaC scanning | Tool runner + parser |
| — | SAST scanning | Tool runner + parser + Premium hook |
| — | M2M API authentication | API key -> JWT flow |
| — | Multi-format output | JSON, Markdown, SARIF |
| — | Report command | Fetches from API, renders text/json/md/pdf |
| — | CI/CD metadata detection | GitHub Actions, GitLab CI, Jenkins |
| — | Docker multi-stage build | Initial image with tools |
| — | Premium Open Core hooks | Conditional import of `gerion_cli/pro/` |
| #1 | Tool binary availability checks | `shutil.which()` in all 4 tool runners |
| #2 | Tempfile for report paths | `tempfile.NamedTemporaryFile` in all 4 runners |
| #3 | Subprocess timeouts | `timeout=180` + dual timeout (tool-level + subprocess) |
| #4 | Replace Semgrep with Opengrep (SAST) | `opengrep` binary, `--disable-version-check`, same output format |
| #5 | Replace Trivy SCA with OSV-Scanner | `osv-scanner scan --format json -r`, UNKNOWN→LOW severity mapping |
| #6 | Replace Trivy IaC with KICS | `kics scan`, `--queries-path` auto-detection, 2400+ queries |
| #7 | Rebuild Dockerfile for new tool stack | Multi-stage: tool-builder + kics-builder (Go + UPX) + cli-builder + debian:bookworm-slim final |
| #8 | Extract Base Scan Command | `commands/base.py` with `run_scan()`, 4 commands reduced to thin wrappers |
| #9 | Audit Tool Outputs & Finding Model | Research only. No normalizable fields found across all scanners worth adding. See `spec/tool_output_audit.md` |
