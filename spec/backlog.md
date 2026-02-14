# Gerion CLI — Backlog

> Gerion CLI is a **scanner orchestrator** that wraps external security tools,
> normalizes findings, and dispatches results to the Gerion API Gateway.
> Priorities are scoped to: tool integration, output quality, robustness,
> and developer experience.

---

## Strategic Context (post-v0.1.0)

The CLI is **functional but early-stage**. Core scanning (SAST, SCA, Secrets, IaC)
works, API integration is complete, and multiple output formats are supported.
T1 stability fixes and T2 tool migrations (code-level) are done.
Remaining: Dockerfile update (#7) to reflect new tool stack.

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
- **Raw dict models**: No validation on findings data structure.

---

## Priority Tiers

| Tier | Goal | Items |
|------|------|-------|
| **T1** | Bugs & Stability | ~~#1, #2, #3~~ DONE |
| **T2** | Tool Migration — Opengrep + OSV-Scanner + KICS | #4, #5, #6, #7 |
| **T3** | Architecture & Quality — DRY, models, tests | #8, #9, #10, #11 |
| **T4** | Features — New capabilities | #12, #13, #14 |

---

## Tier 2 — Tool Migration

### #4 Replace Semgrep with Opengrep (SAST)

**Priority**: HIGH
**Effort**: Medium
**Impact**: Opengrep is the LGPL 2.1 community fork of Semgrep. Same rules/output format, open source aligned.

#### Rationale
Semgrep changed its license (Dec 2024) to restrict commercial use of community rules.
Opengrep is the community-driven fork maintaining full compatibility. Backed by
Endor Labs, Aikido, Orca Security, Jit. Install via binary only — PyPI package
was hijacked by an attacker.

#### Solution
1. **CLI**: Replace `semgrep` binary calls with `opengrep` in `tools/sast.py`
2. **Parser**: Verify Opengrep JSON output is compatible with `parse_sast_tool_output()`.
   Opengrep maintains Semgrep output compatibility, so minimal changes expected.
3. **Dockerfile**: Replace `pip install semgrep==1.97.0` with Opengrep binary install
   via official install script or release binary.
4. **Tool check**: Update `shutil.which("semgrep")` to `shutil.which("opengrep")`
5. **Documentation**: Update README.md, plan.md references

#### Files to Modify
- `gerion_cli/tools/sast.py` — Change command from `semgrep` to `opengrep`
- `gerion_cli/tools/parser.py` — Verify/adapt SAST output parsing (likely no changes)
- `Dockerfile` — Replace Semgrep pip install with Opengrep binary
- `README.md` — Update tool references
- `spec/plan.md` — Update tool references

#### Verification
- Run Opengrep on a test codebase, compare JSON output with Semgrep output
- Ensure `parse_sast_tool_output()` produces identical findings

---

### #5 Replace Trivy SCA with OSV-Scanner

**Priority**: HIGH
**Effort**: Medium
**Impact**: Native OSV format output for Risk Detector compatibility. Broader vulnerability database.

#### Rationale
1. **OSV format compatibility**: Risk Detector's `mapper.rs` already normalizes
   OSV reports natively. CLI output can feed directly into the motor.
2. **Broader database**: OSV aggregates NVD, GitHub Advisory, PyPI, npm, Go, etc.
3. **Focused tool**: OSV-Scanner is SCA-only, unlike Trivy's multi-purpose approach.

#### OSV-Scanner JSON output structure
```json
{
  "results": [{
    "packageSource": { "path": "/path/to/lockfile", "type": "lockfile" },
    "packages": [{
      "package": { "name": "pkg", "version": "1.0", "ecosystem": "PyPI" },
      "vulnerabilities": [{
        "id": "GHSA-xxx",
        "aliases": ["CVE-2024-xxx"],
        "summary": "...",
        "details": "..."
      }]
    }]
  }]
}
```

#### Finding mapping
| OSV-Scanner field | Finding field |
|-------------------|---------------|
| `vulnerabilities[].id` | `cve` (GHSA-xxx or CVE-xxx) |
| `vulnerabilities[].aliases[]` | `cve` (prefer CVE if available in aliases) |
| `vulnerabilities[].summary` | `title` |
| `vulnerabilities[].details` | `description` |
| `packages[].package.name` | `component_name` |
| `packages[].package.version` | `component_version` |
| `affected[].ranges[].events[].fixed` | `component_fix` |
| `database_specific.severity` | `severity` |
| `packageSource.path` | `file_path` |

#### Files to Modify
- `gerion_cli/tools/sca.py` — Replace Trivy command with `osv-scanner scan --format json`
- `gerion_cli/tools/parser.py` — Rewrite `parse_sca_tool_output()` for OSV format
- `Dockerfile` — Install OSV-Scanner Go binary
- `README.md` — Update tool references

#### Verification
- Run OSV-Scanner on a test project, validate findings against Trivy output
- Verify Finding model compatibility with API Gateway

---

### #6 Replace Trivy IaC with KICS

**Priority**: HIGH
**Effort**: Medium
**Impact**: 2400+ queries (vs Trivy's ~500), 15+ IaC formats, Go binary, Apache 2.0. Eliminates Trivy entirely.

#### Rationale
1. **More queries**: 2400+ Rego-based queries vs Trivy's ~500 for IaC
2. **More formats**: Terraform, K8s, Dockerfile, CloudFormation, Helm, Ansible,
   OpenAPI, Pulumi, and 15+ more
3. **Eliminates Trivy**: With OSV-Scanner for SCA (#5) and KICS for IaC,
   Trivy is no longer needed in the stack at all
4. **Go binary**: Lightweight, no Python dependencies
5. **Apache 2.0**: Clean license

#### KICS JSON output structure
KICS outputs JSON with `queries` array containing findings grouped by query ID.
Each finding has severity, file path, line number, expected/actual values, and
remediation guidance.

#### Finding mapping (to verify during implementation)
| KICS field | Finding field |
|------------|---------------|
| `query_name` | `title` |
| `description` | `description` |
| `severity` | `severity` (HIGH, MEDIUM, LOW, INFO) |
| `file_name` | `file_path` |
| `line` | `line_number` |
| `expected_value` / `actual_value` | `mitigation` |
| `query_id` | Used for `finding_id` generation |
| `platform` | Additional context (Terraform, K8s, etc.) |

#### Files to Modify
- `gerion_cli/tools/iac.py` — Replace Trivy command with `kics scan --type json`
- `gerion_cli/tools/parser.py` — Rewrite `parse_iac_tool_output()` for KICS format
- `Dockerfile` — Replace Trivy with KICS binary, remove Trivy entirely
- `README.md` — Update tool references

#### Verification
- Run KICS on test IaC files, compare coverage with Trivy output
- Verify Finding model fields map correctly

---

### #7 Update Dockerfile for New Tool Stack

**Priority**: HIGH (depends on #4, #5, #6)
**Effort**: Low
**Impact**: Docker image reflects final tool choices. Trivy completely removed.

#### Solution
After #4, #5, and #6 are complete:
1. Install **Opengrep** binary (replace `pip install semgrep`)
2. Install **OSV-Scanner** Go binary (from Google releases)
3. Install **KICS** Go binary (from Checkmarx releases)
4. **Remove Trivy** entirely
5. Keep **Gitleaks** for secrets scanning

#### Target Docker image contents
```
/usr/local/bin/opengrep     # SAST
/usr/local/bin/osv-scanner   # SCA
/usr/local/bin/kics          # IaC (+ queries dir)
/usr/local/bin/gitleaks      # Secrets
/usr/local/bin/gerion        # CLI binary
```

#### Files to Modify
- `Dockerfile`

---

## Tier 3 — Architecture & Quality

### #8 Extract Base Scan Command

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

### #9 Add Pydantic Models for Findings

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
| — | Fix duplicate enrich_sast_finding | v0.1.0 | Removed duplicate call in parser.py |
| — | Fix unreachable return statement | v0.1.0 | Removed dead code in parser.py |
| #1 | Tool binary availability checks | v0.1.0 | `shutil.which()` in all 4 tool runners |
| #2 | Tempfile for report paths | v0.1.0 | `tempfile.NamedTemporaryFile` in all 4 runners |
| #3 | Subprocess timeouts | v0.1.0 | `timeout=180` + dual timeout (tool-level + subprocess) |
