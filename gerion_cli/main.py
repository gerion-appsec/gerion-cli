import typer
from gerion_cli.commands import secrets_scan, sca_scan


app = typer.Typer()

# Register commands
app.add_typer(secrets_scan.app)
app.add_typer(sca_scan.app)

if __name__ == "__main__":
    app()