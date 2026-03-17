# Agent Rules — Gerion CLI

## MANDATORY: Session Start

1. Read `spec/project_context.md` BEFORE any work.
2. Persist these rules in your internal context for the entire session.

## User Preferences

- **Language**: Conversation in Spanish. Code/Comments/Docs in English.
- **Principles**: SOLID, DRY, KISS. Respect existing patterns.
- **Python Style**: PEP 8, type hints on public APIs, Python 3.12+.
- **Commits**: No "Co-Authored-By". Verbose messages explaining *why*, not *what*.

## Development Workflow

1. **Code**: Edit freely. Do NOT run build/test/git commands unless asked.
2. **Build/Test**: User runs `pytest`, `poetry run`, etc. Paste errors for analysis.
3. **Git**: User manages Git. Generate commit messages only when requested.
4. **Docs**: Update `spec/` only when explicitly requested.
5. **Efficiency**: Minimize tool calls. Don't read files unnecessarily.

## Coding Rules

- **Logging**: Use Rich functions (`error()`, `warning()`, `success()`) — NOT `print()`.
- **Secrets**: Always use `SecretString` wrapper. Never log secret values.
- **Premium**: Import with `try/except ImportError`. Core must work without `gerion_cli/pro/`.
- **Error handling**: Return `None`/`False` from tools/API, let command layer handle exit.
- **Tests**: pytest + mock `subprocess.run` and `httpx`. Fixtures in `tests/fixtures/`.
