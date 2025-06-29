from typing import Optional
from pydantic import SecretStr

class SecretString:
    """
    A wrapper for SecretStr that can be used with Typer.
    This allows us to use SecretStr functionality while being compatible with Typer.
    """
    
    def __init__(self, value: Optional[str] = None):
        self._secret = SecretStr(value) if value else None
    
    def get_secret_value(self) -> Optional[str]:
        """Get the actual secret value."""
        return self._secret.get_secret_value() if self._secret else None
    
    def __bool__(self) -> bool:
        """Check if the secret has a value."""
        return self._secret is not None and bool(self._secret.get_secret_value())
    
    def __str__(self) -> str:
        """String representation (masked for security)."""
        return "***" if self._secret else ""
    
    @classmethod
    def from_env_var(cls, env_var: str) -> 'SecretString':
        """Create a SecretString from an environment variable."""
        import os
        value = os.getenv(env_var)
        return cls(value) if value else cls()
    
    @classmethod
    def from_typer_option(cls, value: Optional[str]) -> 'SecretString':
        """Create a SecretString from a Typer option value."""
        return cls(value) if value else cls() 