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
| **T2** | Tool Migration — Opengrep + OSV-Scanner + KICS | ~~#4, #5, #6, #7~~ DONE |
| **T3** | Architecture & Quality — DRY, models, tests | #8, #9, #10, #11 |
| **T4** | Features — New capabilities | #12, #13, #14 |

---

## Tier 2 — Tool Migration (COMPLETED)

All migration tasks are done.

### ~~#7 Rebuild Dockerfile for New Tool Stack~~ (DONE)

**Priority**: HIGH
**Effort**: Medium
**Impact**: Docker image reflects final tool choices. Trivy and Semgrep completely removed. All four security tools installed as native binaries.

#### Context

The current `Dockerfile` still installs Trivy (binary from GitHub releases) and
Semgrep (`pip install semgrep==1.97.0`). Both must be replaced. The new image
must contain Gitleaks, Opengrep, OSV-Scanner, KICS, and the Gerion CLI binary.

#### Architecture: Multi-Stage Build

The Dockerfile MUST use a multi-stage build with these stages. Each stage is
described in detail below.

##### Stage 1: `tool-builder` (base: `python:3.13-slim-bookworm`)

Downloads pre-built binaries for Gitleaks, Opengrep, and OSV-Scanner.
Requires `curl` installed via `apt-get`.

**Gitleaks** — Download tarball from GitHub releases:
```dockerfile
ARG GITLEAKS_VERSION=8.24.2
RUN curl -sfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    -o gitleaks.tar.gz && \
    tar -xzf gitleaks.tar.gz -C /usr/local/bin/ gitleaks && \
    rm gitleaks.tar.gz
```
- This pattern already works in the current Dockerfile. Keep it as-is.

**Opengrep** — Download standalone binary from GitHub releases:
```dockerfile
ARG OPENGREP_VERSION=v1.16.0
RUN curl -sfL "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_x86" \
    -o /usr/local/bin/opengrep && \
    chmod +x /usr/local/bin/opengrep
```
- The binary is self-contained (~40 MB), no extraction needed.
- Use the `manylinux` variant (NOT `musllinux`) because the base image is Debian.
- The version ARG MUST include the `v` prefix (e.g. `v1.16.0`).
- **Fallback** (only if direct download fails): use the install script:
  `curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash`
  then copy the binary from `~/.opengrep/cli/latest/opengrep` to `/usr/local/bin/`.

**OSV-Scanner** — Download standalone binary from GitHub releases:
```dockerfile
ARG OSV_SCANNER_VERSION=2.3.3
RUN curl -sfL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
    -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner
```
- Standalone binary (~55 MB), no extraction needed.
- The version ARG must NOT include the `v` prefix, but the URL path does.

##### Stage 2: `kics-builder` (base: `golang:<latest>`)

KICS does NOT publish pre-built binaries on GitHub releases. It MUST be
compiled from source. The repository is very large, so shallow clone is mandatory.

```dockerfile
FROM golang:<latest> AS kics-builder
ARG KICS_VERSION=v2.1.5

RUN apt-get update && apt-get install -y --no-install-recommends \
    git upx-ucl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --depth 1 --branch ${KICS_VERSION} https://github.com/Checkmarx/kics.git .
RUN go build -o /usr/local/bin/kics -ldflags="-s -w" ./cmd/console
RUN upx-ucl -9 /usr/local/bin/kics
```

Key constraints:
- `--depth 1`: The KICS repo is massive. NEVER clone full history.
- `-ldflags="-s -w"`: Strips debug symbols and DWARF info. Reduces binary size.
- `upx-ucl -9`: Compresses the binary further. Without this, the KICS binary
  is excessively large (~100+ MB). After compression it is still significant but
  manageable.
- KICS requires a **queries directory** at runtime. It contains 2400+ Rego
  query files organized by platform. Copy it from the source tree:
  ```dockerfile
  # The queries live in /build/assets/queries/ after clone
  ```
  This directory MUST be available in the final image. The CLI's `tools/iac.py`
  auto-detects it relative to the binary (see `--queries-path` logic).

##### Stage 3: `cli-builder` (same as current Stage 2)

Builds the Gerion CLI Python binary using PyInstaller. Keep the current logic:
```dockerfile
COPY . /gerion_cli
WORKDIR /gerion_cli
RUN pip install poetry pyinstaller && \
    poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi && \
    rm -rf gerion_cli/pro && \
    pyinstaller --name gerion --distpath /usr/local/bin/ --onefile gerion_cli/main.py
```

##### Stage 4: `final` (base: `python:3.13-slim-bookworm`)

Minimal runtime image. Copy all binaries and required data from previous stages.

**Directory layout:**
```
/usr/local/bin/gitleaks          # Secrets scanner
/usr/local/bin/opengrep          # SAST scanner
/usr/local/bin/osv-scanner       # SCA scanner
/usr/local/bin/kics              # IaC scanner
/usr/local/bin/gerion            # CLI binary
/usr/local/share/kics/queries/   # KICS query files (2400+ Rego queries)
```

**COPY directives:**
```dockerfile
COPY --from=tool-builder /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=tool-builder /usr/local/bin/opengrep /usr/local/bin/opengrep
COPY --from=tool-builder /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=kics-builder /usr/local/bin/kics /usr/local/bin/kics
COPY --from=kics-builder /build/assets/queries /usr/local/share/kics/queries
COPY --from=cli-builder /usr/local/bin/gerion /usr/local/bin/gerion
```

**Runtime dependencies:**
- `git` is required (installed via `apt-get`). Gitleaks and Opengrep need it.
- Do NOT install Semgrep (`pip install semgrep`). Do NOT install Trivy.
- Do NOT install Python packages in the final stage (CLI is a standalone binary).

**User setup** (keep existing):
```dockerfile
RUN groupadd -r gerion && useradd -r -g gerion -d /home/gerion -m gerion
RUN mkdir -p /code /output && chown -R gerion:gerion /code /output
WORKDIR /code
USER gerion
ENTRYPOINT ["gerion"]
CMD ["--help"]
```

#### KICS Queries Path Integration

The CLI's `tools/iac.py` already has auto-detection logic that looks for
queries relative to the KICS binary path. With KICS at `/usr/local/bin/kics`
and queries at `/usr/local/share/kics/queries/`, the auto-detection will NOT
find them automatically (it looks at `<binary_dir>/assets/queries/`).

There are two valid solutions (pick ONE):
1. **Symlink**: In the final stage, create a symlink:
   `RUN mkdir -p /usr/local/bin/assets && ln -s /usr/local/share/kics/queries /usr/local/bin/assets/queries`
2. **Environment variable**: Set `ENV KICS_QUERIES_PATH=/usr/local/share/kics/queries`
   and update `tools/iac.py` to read it as a fallback.

Solution 1 (symlink) is preferred because it requires zero code changes.

#### Version ARGs (pinned)

All tool versions MUST be declared as `ARG` at the top of each relevant stage
for easy updates:
```
GITLEAKS_VERSION=8.24.2
OPENGREP_VERSION=v1.16.0
OSV_SCANNER_VERSION=2.3.3
KICS_VERSION=v2.1.5
```

#### What to Remove

- Delete ALL Trivy references (ARG, curl, COPY).
- Delete the `pip install --no-cache-dir semgrep==1.97.0` line.
- Delete `COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy`.

#### Verification

After building the image, run these checks inside the container:
```bash
docker run --rm <image> --version              # gerion-cli responds
docker run --rm --entrypoint gitleaks <image> version
docker run --rm --entrypoint opengrep <image> --version
docker run --rm --entrypoint osv-scanner <image> --version
docker run --rm --entrypoint kics <image> version
```

All five commands must succeed. If any binary is missing or fails, the build
is incorrect.

#### Files to Modify
- `Dockerfile` — Full rewrite following the stages above.

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
