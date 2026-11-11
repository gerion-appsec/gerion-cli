# Changelog

## 1.1.0 — Unreleased

### CI behavior changes

- Scanner execution now fails closed. Missing binaries, timeouts, non-success
  scanner exits and missing or invalid reports return `1` instead of looking like
  an empty successful scan. Scans with no applicable input still succeed.
- Scan commands reserve `2` for invalid CLI usage, return `3` for findings at or
  above `--fail-on`, and return `4` for authentication or API delivery failures.
  When conditions overlap, precedence is `1 > 3 > 4`; diagnostics report each
  detected condition. Without `--fail-on`, findings alone do not fail a scan.
- Update pipelines that previously treated `2` as findings or `1` as an API outage.
  Results are emitted or submitted before the severity gate is evaluated.

### Scanning and API integration

- Add `--fail-on` / `GERION_FAIL_ON` with case-insensitive severity thresholds.
- Run all four scanners concurrently by default, with `--sequential` for smaller
  runners. Preserve fixed output order, each scanner's duration and total elapsed
  time. Continue remaining scans after a failure and emit partial results.
- Terminate scanner process groups on timeout, interruption and SIGTERM, and keep
  temporary scanner reports private and remove them after execution.
- Reuse one API login per run and retry once when a cached token is rejected.
- Use real CI build IDs and PR head commit metadata when available; preserve local
  Git metadata when CI variables are empty. Read Git metadata through the git
  executable, including detached checkouts, without requiring GitPython.
- Normalize secrets severities to uppercase. Preserve existing finding IDs to
  retain deduplication, false-positive decisions and finding history.

### Packaging and output

- Use PEP 621 metadata, Hatchling and uv with a tracked lockfile. Remove Poetry,
  Pydantic and GitPython from runtime dependencies.
- Install the container CLI as a regular Python package so premium plugins can be
  discovered through entry points. Precompile Python bytecode and lazily load API
  and PDF dependencies to reduce startup cost.
- Pin scanner downloads and verify checksums; pin the KICS source commit. Bundle
  KICS queries. Versions: Gitleaks 8.30.1, Opengrep 1.33.1, OSV-Scanner 2.7.0,
  KICS 2.2.0.
- Validate API URL/TLS settings and support `GERION_CA_BUNDLE` for private CAs.
- Improve file-write diagnostics and escaping of finding content in reports.

### Companion repositories

- Premium reuses the base image's Python CLI and `gerion` entry point, installs
  only the plugin and motor, and corrects the Compose Dockerfile path. The native
  motor wheel must match the base image's Python 3.13 and target architecture.
- The GitHub Action forwards run and PR event metadata, supports `fail-on`, and
  preserves the CLI exit-code output on failure. Use companion revisions
  containing these changes; they are released separately.

This release is prepared on `release/1.1.0`. No release tag or published image is
created by preparing these notes.
