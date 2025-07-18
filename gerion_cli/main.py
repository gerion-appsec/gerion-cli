import typer
from gerion_cli.commands import secrets_scan, sca_scan, iac_scan


app = typer.Typer(no_args_is_help=True)

# Register commands
app.add_typer(secrets_scan.app)
app.add_typer(sca_scan.app)
app.add_typer(iac_scan.app)

if __name__ == "__main__":
    app()