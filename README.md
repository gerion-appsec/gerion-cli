# Gerion CLI

A unified command-line interface for running security scans on codebases. Gerion CLI orchestrates multiple open-source scanning tools, normalizes their output into a consistent finding model, and optionally forwards results to the Gerion API Gateway for centralized management.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](Dockerfile)

---

## Scan types

| Type | Tool | Version | Detects |
|------|------|---------|---------|
| SAST | [Opengrep](https://github.com/opengrep/opengrep) | 1.33.1 | Code vulnerabilities and anti-patterns |
| SCA | [OSV-Scanner](https://github.com/google/osv-scanner) | 2.7.0 | Vulnerable dependencies (CVEs) |
| IaC | [KICS](https://github.com/Checkmarx/kics) | 2.2.0 | Infrastructure as Code misconfigurations |
| Secrets | [Gitleaks](https://github.com/gitleaks/gitleaks) | 8.30.1 | Hardcoded secrets and credentials |

---

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- `git` in `PATH` to read repository metadata (repository, branch, commit, author); without it scans still run with default metadata
- Linux or macOS, x86_64 or arm64 (scanner binaries are downloaded for your platform and verified against pinned SHA-256 checksums)
- [Go](https://go.dev/doc/install) 1.26.2+ to build KICS from source (it publishes no prebuilt binaries)

---

## Installation

### With Make (recommended)

```sh
git clone https://github.com/gerion-appsec/gerion-cli.git
cd gerion-cli
make install
```

`make install` installs Python dependencies via uv and downloads all scanner binaries to `$HOME/.local/bin/`. Make sure that directory is in your `PATH`.

Individual targets are also available:

```sh
make install-python       # uv sync only
make gitleaks             # Install Gitleaks only
make opengrep             # Install Opengrep only
make osv-scanner          # Install OSV-Scanner only
make kics                 # Install KICS only

make uninstall            # Uninstall everything
make check                # Verify all tools are available in PATH
make test                 # Run the test suite (pytest)
make lint                 # Run ruff
make clean                # Uninstall everything and remove the virtual environment (`.venv`)
```

### With Docker

The Docker image bundles all scanner binaries and the CLI in a single image (linux/amd64 and linux/arm64). No local installation required. The CLI is installed as a regular Python package, and every downloaded scanner binary is verified against a pinned SHA-256 at build time.

```sh
docker build -t gerion-cli .
docker run --rm gerion-cli --help
```

---

## Configuration

Credentials and API endpoint are read from environment variables:

```sh
export GERION_API_URL="https://api.gerion.dev"
export GERION_API_KEY="your-m2m-api-key"
```

Use an `https://` API URL: the API key is sent to it. Plain `http://` is accepted for local development but prints a warning unless the host is `localhost`, `127.0.0.1` or `::1`. To trust a private CA, set `GERION_CA_BUNDLE` to a PEM file or to a directory of hashed certificates.

Use `env.example` as a template and export its variables in your shell or CI environment; the CLI does not load `.env` files automatically. Command options can also be passed as CLI flags.

The `CLIENT_ID` is set automatically to `gerion-cli-{version}` (e.g. `gerion-cli-1.1.0`). It can be overridden with `GERION_CLIENT_ID` if needed.

---

## Usage

### Running a scan

```sh
# With uv
uv run gerion sast-scan [CODE_PATH] [OPTIONS]

# With Docker
docker run --rm -v "$PWD:/code" gerion-cli sast-scan /code
```

Each scan command accepts the same core set of options:

| Option | Env var | Description |
|--------|---------|-------------|
| `--api-url` | `GERION_API_URL` | Gerion API Gateway base URL |
| `--api-key` | `GERION_API_KEY` | M2M API key for authentication |
| `--client-id` | `GERION_CLIENT_ID` | Client identifier (default: `gerion-cli-{version}`) |
| `--output-file` | — | Write results to a file (suppresses API and console output) |
| `--format` | — | Output format for stdout: `json`, `markdown`, `sarif`, `table` |
| `--timeout` | — | Scanner execution timeout in seconds (default: 180) |
| `--fail-on` | `GERION_FAIL_ON` | Exit with code 3 if any finding has at least this severity: `critical`, `high`, `medium`, `low` (default: unset, findings never fail the command) |
| `--log-level` | — | Logging verbosity: `debug`, `info`, `warning`, `error`, `critical` |

The IaC scan additionally accepts `--queries-path` to specify a custom KICS queries directory.

The SCA scan uses OSV-Scanner with the `--no-resolve` flag. This disables dynamic/estimated dependency resolution for open manifests (like `requirements.txt`) to prevent false positives caused by resolving to the minimum compatible versions of transitive dependencies. For projects utilizing lockfiles (such as `poetry.lock`, `package-lock.json`, etc.), transitive dependencies are still fully analyzed since they are already explicitly declared in the lockfile.

### Output routing

When a scan completes, output is dispatched according to this priority:

1. `--output-file` — writes to file; format inferred from extension or set with `--format`
2. `--format` — prints to stdout in the chosen format
3. API credentials present — sends results to the Gerion API Gateway
4. Fallback — displays a findings table in the console

### Scan all

Runs all four scan types and aggregates the results:

```sh
uv run gerion scan-all [CODE_PATH] [OPTIONS]
```

The four scanners run in parallel; their results are always parsed and reported in the same order (Secrets, SCA, IaC, SAST). Each scan keeps its own `scan_duration`, while the summary and the aggregated metadata's `scan_duration` report the wall-clock time of the whole command. On small CI runners, `--sequential` runs the scanners one after another for a lower peak CPU and memory use. `--timeout` applies to each scanner.

When `--output-file` or `--format` is set, individual scan outputs are suppressed and the combined results are handled at the end. The output format is inferred from the file extension exactly as for single scans.

Every scan runs even if another one fails. The results of the scans that succeeded are still emitted, the summary lists the failed scans, and the command exits with code 1.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | The scan completed and, if `--fail-on` is set, no finding reached the threshold. |
| `1` | A scanner could not run or failed (binary not in `PATH`, timeout, unexpected scanner exit code, missing or invalid report), or an unexpected command/output error prevented completion. |
| `2` | Invalid command-line usage (Typer/Click validation). |
| `3` | `--fail-on` is set and at least one finding has that severity or higher. Results are output or uploaded as usual first. |
| `4` | Authentication or delivery to the API failed; the scan results were not stored. |

For scan commands, precedence is `1 > 3 > 4`. All detected problems are reported even when a higher-priority code wins. `scan-all` evaluates `--fail-on` across all completed scans. Findings with an unknown or missing severity count as `low`. Without API credentials the CLI runs in console mode, which is not a failure; with credentials, a failed upload still prints the findings table but exits `4` unless a higher-priority condition applies.

A project with nothing to scan (for example no dependency manifests for SCA) is a completed scan with no findings, not an error.

### Report

Fetches findings from the API Gateway and renders a report:

```sh
uv run gerion report [PATH] [OPTIONS]
```

| Option | Short | Description |
|--------|-------|-------------|
| `--repo` | `-r` | Override repository name filter |
| `--branch` | `-b` | Override branch name filter |
| `--type` | `-t` | Filter by scan type: `SAST`, `SCA`, `IaC`, `SECRETS` |
| `--severity` | `-s` | Minimum severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `--format` | `-f` | Report format: `text`, `json`, `markdown`, `pdf` (default: `text`) |
| `--output-file` | `-o` | Write report to file |
| `--active-only` / `--all` | — | Include only active findings (default: `--active-only`) |
| `--include-description` / `--no-description` | — | Include finding descriptions (default: on) |
| `--include-mitigation` / `--no-mitigation` | — | Include remediation guidance (default: on) |
| `--api-url` | `-u` | Gerion API Gateway base URL |
| `--api-key` | `-k` | M2M API key |

---

## CI/CD integration

### GitHub Actions

```yaml
- name: Gerion security scan
  env:
    GERION_API_URL: ${{ secrets.GERION_API_URL }}
    GERION_API_KEY: ${{ secrets.GERION_API_KEY }}
  run: |
    docker run --rm -v "$PWD:/code" \
      -e GERION_API_URL -e GERION_API_KEY \
      gerion-cli scan-all /code --fail-on high   # exit 3 on HIGH or CRITICAL findings
```

### GitLab CI

```yaml
gerion-scan:
  image: gerion-cli:latest
  script:
    # GERION_API_URL and GERION_API_KEY are read from the CI/CD variables
    - gerion scan-all . --fail-on high
```

Prefer passing the API key through the `GERION_API_KEY` environment variable rather than `--api-key`: command-line arguments are visible to other processes on the machine.

### Scan metadata

Scan results include Git metadata (repository, branch, commit hash, author, build ID, code path). It starts from the local Git repository, is overridden by the CI platform's variables (only when they are set and non-empty), and finally by the `GERION_*` variables.

| Platform | Variables read |
|----------|----------------|
| GitHub Actions (detected by `GITHUB_SERVER_URL`) | `GITHUB_REPOSITORY`, `GITHUB_HEAD_REF` / `GITHUB_REF_NAME`, `GITHUB_RUN_ID` (falls back to `GITHUB_RUN_ATTEMPT`), `GITHUB_WORKSPACE`, `GITHUB_ACTOR`. Commit: PR head SHA from `GITHUB_EVENT_PATH` on `pull_request*` events (`GITHUB_EVENT_NAME`), else `GITHUB_SHA`, else `GITHUB_WORKFLOW_SHA` |
| GitLab CI | `CI_PROJECT_NAME`, `CI_MERGE_REQUEST_SOURCE_BRANCH_NAME` / `CI_COMMIT_REF_NAME`, `CI_PIPELINE_ID` (falls back to `CI_JOB_ID`, then `CI_CONCURRENT_ID`), `CI_PROJECT_DIR` (falls back to `CI_BUILDS_DIR`), `CI_COMMIT_SHA`, `CI_COMMIT_AUTHOR` |
| Jenkins | `GIT_URL`, `GIT_BRANCH`, `BUILD_NUMBER`, `WORKSPACE`, `GIT_COMMIT`, `GIT_COMMITTER_NAME` |
| Manual overrides | `GERION_REPO_NAME`, `GERION_BRANCH_NAME`, `GERION_COMMIT_HASH`, `GERION_BUILD_ID` |

The API expects `build_id` to be numeric: CI detection only uses numeric values and otherwise keeps `0`, and a non-numeric `GERION_BUILD_ID` prints a warning. Scans are stored per (organization, branch, scan type, build ID), so a build ID that is unique per run keeps one scan per run.

The updated official GitHub Action forwards `GITHUB_RUN_ID`, `GITHUB_ACTIONS`, `GITHUB_EVENT_NAME` and the other metadata variables, and mounts `GITHUB_EVENT_PATH` read-only when available. This preserves per-run history and lets the CLI record PR head commits. Use an Action revision containing this update; older revisions fall back to `GITHUB_RUN_ATTEMPT` and `GITHUB_SHA`.


---

## Contributing

1. Fork this repository.
2. Create a branch for your change.
3. Commit your changes with a descriptive message.
4. Open a pull request.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

## Links

- [Issues](https://github.com/gerion-appsec/gerion-cli/issues)
- [gerion.dev](https://gerion.dev)
