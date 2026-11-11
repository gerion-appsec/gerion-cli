import signal

import typer

from gerion_cli.commands import iac_scan, report, sast_scan, sca_scan, scan_all, secrets_scan
from gerion_cli.core.config import __version__


def version_callback(value: bool):
    """Callback to handle --version flag."""
    if value:
        print(f"gerion {__version__}")
        raise typer.Exit()


def _exit_on_sigterm(signum, frame):
    # Scanners run in their own sessions and do not see a SIGTERM sent to the CLI:
    # unwind instead of dying, so they are killed and temporary reports are removed.
    raise SystemExit(128 + signum)


app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)

# Add version option to the main app
@app.callback(invoke_without_command=True)
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the version and exit.",
        callback=version_callback,
        is_eager=True
    )
):
    """Gerion CLI - A powerful command-line interface for performing security scans."""
    signal.signal(signal.SIGTERM, _exit_on_sigterm)

# Register commands
app.command(name="secrets-scan", help="Scan codebase for hardcoded secrets (API keys, passwords, tokens).")(secrets_scan)
app.command(name="sca-scan", help="Scan dependencies for known vulnerabilities (SCA - Software Component Analysis).")(sca_scan)
app.command(name="iac-scan", help="Scan Infrastructure as Code files for misconfigurations.")(iac_scan)
app.command(name="sast-scan", help="Scan code for security vulnerabilities using Opengrep (SAST).")(sast_scan)
app.command(name="scan-all", help="Run all security scans (Secrets, SCA, IaC, SAST) in parallel.")(scan_all)
app.command(name="report", help="Generate a security report for the current project or specified filters.")(report)

if __name__ == "__main__":
    app()
