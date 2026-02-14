# Gerion CLI — Backlog

> Gerion CLI is a **scanner orchestrator** that wraps external security tools,
> normalizes findings, and dispatches results to the Gerion API Gateway.
> Priorities are scoped to: tool integration, output quality, robustness,
> and developer experience.

---

## Strategic Context (post-v0.1.0)

The CLI is **functional and stable**. All planned tiers (T1–T4) are complete.
Core scanning works with the new tool stack (Opengrep, OSV-Scanner, KICS,
Gitleaks), commands share a DRY base, output formats are typed, unit tests
exist, and feature additions (scan-all, duration tracking) are in place.

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
- **Raw dict models**: Findings use raw dicts (no Pydantic in CLI). Evaluated in #9 —
  validation lives in the API Gateway (`InputFinding`), duplicating models here
  would create a sync burden with no real benefit.

---

## Priority Tiers

| Tier | Goal | Items |
|------|------|-------|
| **T1** | Bugs & Stability | ~~#1, #2, #3~~ DONE |
| **T2** | Tool Migration — Opengrep + OSV-Scanner + KICS | ~~#4, #5, #6, #7~~ DONE |
| **T3** | Architecture & Quality — DRY, models, tests | ~~#8, #9, #10, #11~~ DONE |
| **T4** | Features — New capabilities | ~~#12, #13, #14~~ DONE |

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
| #10 | Unify Output Format System | Separate typed enums per command (`OutputFormat` for scans, `ReportFormat` for report). Single enum rejected — format sets are inherently different |
| #11 | Add Unit Tests | 5 test files + 4 fixtures. Covers parsers, metadata, auth, finding template, output formats |
| #12 | Add Scan Duration Tracking | `scan_duration` in metadata via `time.time()` in `base.py`. Included in panel summary and API payload |
| #13 | Add `scan-all` Command | `commands/scan_all.py` runs all 4 scans sequentially via `run_scan()` |
| #14 | Migrate Tool Runners to Logging | All `print()` replaced with `error()`/`warning()` in 4 tool runners |
