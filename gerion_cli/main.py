import typer
from gerion_cli.commands import secrets_scan

app = typer.Typer()

# Register commands
app.add_typer(secrets_scan.app)

if __name__ == "__main__":
    app()