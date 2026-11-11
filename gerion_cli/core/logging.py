"""
Logging functionality for Gerion CLI.
"""
import logging
from enum import StrEnum

from rich.console import Console
from rich.logging import RichHandler
from rich.markup import escape

# Global console instance for logging (stderr)
console = Console(stderr=True)


class LogLevel(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class GerionLogger:
    def __init__(self, log_level: LogLevel = LogLevel.INFO):
        self.log_level = log_level
        self.logger = logging.getLogger("gerion")
        self.logger.setLevel(getattr(logging, log_level.upper()))

        # Remove existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        # Add Rich handler for beautiful formatting
        rich_handler = RichHandler(
            console=console,
            show_time=False,
            show_path=False,
            markup=True,
            rich_tracebacks=False
        )
        rich_handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(rich_handler)

    # Messages routinely embed untrusted text (file paths, scanner stderr, API
    # responses). They are escaped so a stray "[/red]" cannot raise MarkupError
    # or restyle the output.

    def debug(self, message: str):
        self.logger.debug(f"[dim]{escape(str(message))}[/dim]")

    def info(self, message: str):
        self.logger.info(f"[blue]{escape(str(message))}[/blue]")

    def warning(self, message: str):
        self.logger.warning(f"[yellow]⚠️  {escape(str(message))}[/yellow]")

    def error(self, message: str):
        self.logger.error(f"[red]❌ {escape(str(message))}[/red]")

    def success(self, message: str):
        console.print(f"[green]✅ {escape(str(message))}[/green]")

    def panel(self, title: str, content: str, style: str = "blue"):
        from rich.panel import Panel
        from rich.text import Text
        console.print(Panel(Text(content), title=escape(title), style=style))


# Global logger instance
_logger: GerionLogger | None = None


def get_logger() -> GerionLogger:
    global _logger
    if _logger is None:
        _logger = GerionLogger()
    return _logger


def set_log_level(log_level: LogLevel):
    global _logger
    _logger = GerionLogger(log_level)


def debug(message: str):
    get_logger().debug(message)


def info(message: str):
    get_logger().info(message)


def warning(message: str):
    get_logger().warning(message)


def error(message: str):
    get_logger().error(message)


def success(message: str):
    get_logger().success(message)


def panel(title: str, content: str, style: str = "blue"):
    get_logger().panel(title, content, style)
