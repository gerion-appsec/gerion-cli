import typer
from typing import Optional
from gerion_cli.commands import secrets_scan, sca_scan, iac_scan, sast_scan, report
from gerion_cli.core.config import __version__


def version_callback(value: bool):
    """Callback to handle --version flag."""
    if value:
        print(f"gerion-cli {__version__}")
        raise typer.Exit()


app = typer.Typer(no_args_is_help=True)

# Add version option to the main app
@app.callback(invoke_without_command=True)
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the version and exit.",
        callback=version_callback,
        is_eager=True
    )
):
    """Gerion CLI - A powerful command-line interface for performing security scans."""
    pass

# Register commands
app.command(name="secrets-scan", help="Scan codebase for hardcoded secrets (API keys, passwords, tokens).")(secrets_scan)
app.command(name="sca-scan", help="Scan dependencies for known vulnerabilities (SCA - Software Component Analysis).")(sca_scan)
app.command(name="iac-scan", help="Scan Infrastructure as Code files for misconfigurations.")(iac_scan)
app.command(name="sast-scan", help="Scan code for security vulnerabilities using Semgrep (SAST).")(sast_scan)
app.command(name="report", help="Generate a security report for the current project or specified filters.")(report)

if __name__ == "__main__":
    app()