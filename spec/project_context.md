# Project Context for LLMs

## Identity and boundaries

**Project:** Gerion CLI 1.1.1 (see `pyproject.toml`).
**Runtime:** Python 3.12+; container Python 3.13.
**Purpose:** Orchestrate SAST, SCA, Secrets and IaC scanners, normalize findings,
collect repository/CI metadata, render output and submit scans to the API Gateway.

The CLI delegates analysis to external tools. The Gateway/Data API owns schema
validation, persistence, deduplication and finding lifecycle state. Findings and
metadata in the CLI are plain dictionaries, not Pydantic models.

## Stack and packaging

| Concern | Implementation / declared constraint |
|---------|---------------------------------------|
| CLI | Typer `>=0.29.1,<1.0` (Click) |
| HTTP | httpx `>=0.28.1,<1.0`, synchronous and loaded lazily |
| Terminal | Rich `>=15.0,<16.0` |
| PDF | fpdf2 `>=2.9.0,<3.0`, loaded lazily |
| Versions | packaging `>=26.0` |
| Git metadata | Read-only `git` subprocess calls; no GitPython |
| Secrets | Custom `SecretString` class; no Pydantic dependency |
| Build | PEP 621 + Hatchling `>=1.33,<2` |
| Dependencies | uv, tracked `uv.lock`; dev group: pytest, pytest-cov, Ruff |

`gerion` is the console script (`gerion_cli.main:app`). The installed distribution
version comes from `importlib.metadata`; a source-only fallback is in
`core/config.py`. Default client ID: `gerion-cli-{version}`.

```sh
uv sync --locked
uv run gerion --help
uv run pytest
uv run ruff check .
uv build
```

`make install` runs uv sync and installs scanner binaries into `$HOME/.local/bin`.
KICS is built from source and requires Go 1.26.2+. `env.example` is a template;
variables must be exported by the shell or CI, not automatically loaded from `.env`.

## External scanners

| Scanner | Version | Invocation / interpretation |
|---------|---------|-----------------------------|
| Gitleaks | 8.30.1 | `gitleaks dir PATH --exit-code 0 -f json -r REPORT` |
| Opengrep | 1.33.1 | `opengrep scan --config auto --json --output REPORT --disable-version-check PATH` |
| OSV-Scanner | 2.7.0 | `osv-scanner scan --no-resolve --format json --output-file REPORT -r PATH` |
| KICS | 2.2.0 | `kics scan --path PATH --output-path DIR --output-name NAME --report-formats json --ignore-on-exit results --no-color --ci` |

OSV exits 0/1 for a completed scan; 128 means no package sources and produces an
empty successful scan. Other scanner errors, missing binaries, timeouts and
missing/invalid reports raise `ToolError`. KICS uses an explicit `--queries-path`
or auto-detects `assets/queries` next to its binary. OSV disables estimated
resolution for open manifests; lockfile dependencies remain available.

`tools/_runner.py` owns execution and temporary reports. It creates private
temporary directories, starts subprocesses in their own sessions, kills their
process groups on timeout/interruption and removes reports on every exit path.
The CLI timeout bounds scanner execution; it is not a scanner rule timeout.

## Source map

| Path | Responsibility |
|------|----------------|
| `gerion_cli/main.py` | Typer app, version callback, SIGTERM handling |
| `commands/base.py` | Execute, normalize/enrich, dispatch, severity gate and final status |
| `commands/*_scan.py` | Thin wrappers for each scanner |
| `commands/scan_all.py` | Parallel/sequential orchestration and aggregate output |
| `commands/report.py` | Fetch findings and render text, JSON, Markdown or PDF |
| `tools/_runner.py` | Shared subprocess lifecycle and `ToolError` |
| `tools/{secrets,sca,iac,sast}.py` | Scanner command construction/report shape checks |
| `tools/parser.py` | Normalization, redaction, finding templates/IDs |
| `core/{config,types,logging,metadata}.py` | Configuration, enums, secrets, Rich logs, Git/CI context |
| `api/{auth,client,http}.py` | M2M login, token reuse, delivery, URL/TLS settings |
| `output/{formats,tables}.py` | File/stdout formatting, SARIF and Rich tables |
| `tests/` | Parser, runner, API, metadata, output, report, startup and exit-code regressions |
| `.github/workflows/` | Python 3.12/3.13/3.14 checks; container publishing |

## Scan lifecycle

1. Resolve options, secret wrapper and metadata.
2. Execute scanner, record elapsed time; a failed scan cannot count as clean.
3. Normalize findings and call optional premium enrichers.
4. Emit results according to output routing.
5. Evaluate `--fail-on` and choose the final exit status.

Output priority is `--output-file`, explicit `--format`, API credentials, console
table. A file suppresses API and stdout findings; format is explicit or inferred
from its extension. JSON, Markdown and SARIF are file formats; table is console
output. A failed API upload displays the findings table and is recorded as failure.

`scan-all` uses a thread pool for the four independent scanner subprocesses, or
runs sequentially with `--sequential`. Metadata is collected once. Parsing,
enrichment and output follow fixed order: Secrets, SCA, IaC, SAST. Each completed
scan retains its duration; aggregate duration is total wall-clock time. Every
scanner is attempted despite other failures. Partial results are emitted and the
summary identifies missing scans and failed uploads. Aggregate file/stdout output
suppresses per-scan dispatch; API mode submits each completed scan separately.

## Scan exit-code contract

| Code | Meaning |
|------|---------|
| 0 | Complete scan; no findings reach the configured threshold |
| 1 | Scanner failure or unexpected command/output error |
| 2 | Invalid CLI usage (Typer/Click) |
| 3 | Findings at or above `--fail-on` |
| 4 | Authentication or API delivery failure |

Precedence: `1 > 3 > 4`. Detected failures and gate violations are logged even
when a higher-priority condition wins. The gate evaluates completed scan findings
and does not stop output or delivery. Severity thresholds are `critical`, `high`,
`medium`, `low`, case-insensitive, also read from `GERION_FAIL_ON`. Missing/unknown
severities count as low. Without a threshold, findings do not fail the command.
Console mode without API credentials succeeds. The report command has its own
error handling (currently abort/code 1); code 4 describes scan delivery.

## Finding and metadata contracts

A scan result is `{'metadata': {...}, 'findings': [...]}`. Finding fields include
`finding_id`, `title`, `description`, `mitigation`, `severity`, `security_scope`,
`scan_type`, repository/branch/build/commit context, `file_path`, `line_number`,
component name/version/fix, CWE/CVE, lifecycle booleans and timestamps. Parsers
normalize severities and redact secret values before output or delivery.

Finding IDs retain the existing SHA-256 truncated to 12 hexadecimal characters,
computed from concatenated scanner-specific fields. Changing concatenation or
adding separators changes existing identities and can reset lifecycle/false-positive
history. Secret-based IDs include raw secret material that is not persisted, so a
future identity migration needs coordinated CLI/backend support (for example,
legacy and new IDs in a transition). Do not change IDs as a local cleanup.

Metadata fields include repository name, branch, numeric build ID, code path,
commit hash/author, CI platform, scan type and duration. Priority is Git/defaults,
then non-empty CI values, then manual `GERION_*` overrides.

| Source | Main variables |
|--------|----------------|
| GitHub | `GITHUB_REPOSITORY`, `GITHUB_HEAD_REF`/`GITHUB_REF_NAME`, `GITHUB_RUN_ID` then `GITHUB_RUN_ATTEMPT`, `GITHUB_WORKSPACE`, `GITHUB_ACTOR` |
| GitHub commit | PR head from `GITHUB_EVENT_PATH` on `pull_request*`; otherwise `GITHUB_SHA`, then `GITHUB_WORKFLOW_SHA` |
| GitLab | `CI_PROJECT_NAME`, MR source/ref, `CI_PIPELINE_ID`/`CI_JOB_ID`/`CI_CONCURRENT_ID`, `CI_PROJECT_DIR`/`CI_BUILDS_DIR`, SHA/author |
| Jenkins | `GIT_URL`, `GIT_BRANCH` (strip `origin/`), `BUILD_NUMBER`, `WORKSPACE`, `GIT_COMMIT`, `GIT_COMMITTER_NAME` |
| Manual | `GERION_REPO_NAME`, `GERION_BRANCH_NAME`, `GERION_COMMIT_HASH`, `GERION_BUILD_ID` |

CI build IDs must be numeric; missing valid IDs fall back to `0`. Non-numeric manual
build IDs warn. Git metadata survives detached HEAD and missing CI values. CI
platform detection and metadata overrides are separate (GitHub platform detection
uses `GITHUB_ACTIONS`; GitHub overrides use `GITHUB_SERVER_URL`).

## API and reports

M2M login: `POST /api/v1/auth/m2m/authenticate`. Submission:
`POST /api/v1/findings` with `findings_data.scan_metadata` and
`findings_data.findings`. Tokens are cached per API URL/client ID for a run;
a rejected token (401) is refreshed and retried once. HTTP timeout is 60 seconds,
connect timeout 10 seconds. HTTPS uses verified certificates; `GERION_CA_BUNDLE`
accepts a CA file or hashed certificate directory. Plain HTTP to a non-loopback
host warns. API key text must not appear in logs.

`report` fetches `GET /api/v1/reporting/findings`, with repository/branch/type/
severity/activity filters and a limit of 1000. At that limit it warns that results
may be truncated. Formats: text, JSON, Markdown, PDF; PDF requires `--output-file`.

## Container and Premium

The Dockerfile has five stages: checksum-verified scanner downloads, pinned KICS
source build, locked requirements export, CLI wheel build, final image. Final is
Python 3.13 slim with git, certificates, scanners, KICS queries and the CLI installed
as a normal Python distribution. Dependencies use hashes from `uv.lock`; bytecode
is precompiled. Runs as non-root `gerion`, entry point `gerion`, default `--help`.
`/code` and `/output` are available; runtime caches use `/tmp`.

Premium is a separate package discovered from `gerion.enrichers` entry points.
Discovery is cached. Plugin load/enrichment errors warn; the core works without
Premium. There is no bundled `gerion_cli/pro/`; the public image excludes it.
The companion Premium image reuses the Python CLI and installs only plugin/motor;
the native wheel must match Python 3.13 and target architecture. The updated
GitHub Action forwards CI identity and mounts the PR event read-only. Companion
repository changes require their own releases.

## Known limits

- CLI dictionaries intentionally defer API schema validation to the backend.
- Report fetching is capped at 1000 findings; it does not paginate.
- Finding IDs retain legacy concatenation to preserve stored identities.
- `--log-level` is per-command; optional enrichers degrade with warnings.
- Existing legacy Poetry/PyInstaller files may remain locally ignored; they are
  not the current packaging or container build workflow.
