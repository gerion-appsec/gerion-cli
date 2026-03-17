# Gerion CLI

A unified command-line interface for running security scans on codebases. Gerion CLI orchestrates multiple open-source scanning tools, normalizes their output into a consistent finding model, and optionally forwards results to the Gerion API Gateway for centralized management.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](Dockerfile)

---

## Scan types

| Type | Tool | Version | Detects |
|------|------|---------|---------|
| SAST | [Opengrep](https://github.com/opengrep/opengrep) | 1.16.0 | Code vulnerabilities and anti-patterns |
| SCA | [OSV-Scanner](https://github.com/google/osv-scanner) | 2.3.3 | Vulnerable dependencies (CVEs) |
| IaC | [KICS](https://github.com/Checkmarx/kics) | 2.1.5 | Infrastructure as Code misconfigurations |
| Secrets | [Gitleaks](https://github.com/gitleaks/gitleaks) | 8.24.2 | Hardcoded secrets and credentials |

---

## Requirements

- Python 3.12+
- [Poetry](https://python-poetry.org/)
- Linux x86_64 (scanner binaries are fetched for this platform)

---

## Installation

### With Make (recommended)

```sh
git clone https://github.com/gerion-appsec/gerion-cli.git
cd gerion-cli
make install
```

`make install` installs Python dependencies via Poetry and downloads all scanner binaries to `$HOME/.local/bin/`. Make sure that directory is in your `PATH`.

Individual targets are also available:

```sh
make install-python       # Poetry install only
make install-tools        # All scanner binaries only
make install-gitleaks
make install-opengrep
make install-osv-scanner
make install-kics

make check                # Verify all tools are available in PATH
make clean                # Remove the Poetry virtual environment
```

### With Docker

The Docker image bundles all scanner binaries and the CLI in a single image. No local installation required.

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

Copy `env.example` to `.env` for local development. All options can also be passed directly as CLI flags on each command.

The `CLIENT_ID` is set automatically to `gerion-cli-{version}` (e.g. `gerion-cli-0.1.0`). It can be overridden with `GERION_CLIENT_ID` if needed.

---

## Usage

### Running a scan

```sh
# With Poetry
poetry run gerion sast-scan [CODE_PATH] [OPTIONS]

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
| `--log-level` | — | Logging verbosity: `debug`, `info`, `warning`, `error`, `critical` |

The IaC scan additionally accepts `--queries-path` to specify a custom KICS queries directory.

### Output routing

When a scan completes, output is dispatched according to this priority:

1. `--output-file` — writes to file; format inferred from extension or set with `--format`
2. `--format` — prints to stdout in the chosen format
3. API credentials present — sends results to the Gerion API Gateway
4. Fallback — displays a findings table in the console

### Scan all

Runs all four scan types sequentially and aggregates the results:

```sh
poetry run gerion scan-all [CODE_PATH] [OPTIONS]
```

When `--output-file` or `--format` is set, individual scan outputs are suppressed and the combined results are handled at the end.

### Report

Fetches findings from the API Gateway and renders a report:

```sh
poetry run gerion report [PATH] [OPTIONS]
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
  run: |
    docker run --rm -v "$PWD:/code" \
      -e GERION_API_URL=${{ secrets.GERION_API_URL }} \
      -e GERION_API_KEY=${{ secrets.GERION_API_KEY }} \
      gerion-cli scan-all /code
```

### GitLab CI

```yaml
gerion-scan:
  image: gerion-cli:latest
  script:
    - gerion scan-all . --api-url $GERION_API_URL --api-key $GERION_API_KEY
```

Scan results include full Git metadata (repository, branch, commit hash, author, build ID) sourced from environment variables or the local Git repository.

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
- [Gerion AppSec](https://gerion-appsec.com)
