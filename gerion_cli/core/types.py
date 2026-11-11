"""
Custom types for Gerion CLI.
"""
import os
from enum import StrEnum


class OutputFormat(StrEnum):
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"
    TABLE = "table"


class FailOn(StrEnum):
    """Minimum finding severity that makes a scan exit with code 3 (--fail-on)."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SecretString:
    """
    Holds a secret (API key) without ever exposing it through str()/repr().

    The value is only reachable through get_secret_value(), so an accidental
    f-string, log call or traceback dump prints a mask instead of the secret.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str | None = None):
        self._value = value or None

    def get_secret_value(self) -> str | None:
        """Get the actual secret value."""
        return self._value

    def __bool__(self) -> bool:
        """Check if the secret has a value."""
        return self._value is not None

    def __str__(self) -> str:
        """String representation (masked for security)."""
        return "***" if self._value else ""

    def __repr__(self) -> str:
        return f"SecretString('{self}')"

    @classmethod
    def from_env_var(cls, env_var: str) -> "SecretString":
        """Create a SecretString from an environment variable."""
        return cls(os.getenv(env_var))

    @classmethod
    def from_typer_option(cls, value: str | None) -> "SecretString":
        """Create a SecretString from a Typer option value."""
        return cls(value)
