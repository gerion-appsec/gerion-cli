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
2. **Build/Test**: User runs `uv run pytest`, `uv run ruff check .`, etc. Paste errors for analysis.
3. **Git**: User manages Git. Generate commit messages only when requested.
4. **Docs**: Update `spec/` only when explicitly requested.
5. **Efficiency**: Minimize tool calls. Don't read files unnecessarily.

## Coding Rules

- **Logging**: Use Rich functions (`error()`, `warning()`, `success()`) — NOT `print()`.
- **Secrets**: Always use `SecretString` wrapper. Never log secret values.
- **Premium**: Discover optional plugins through the `gerion.enrichers` entry-point group. Core must work without any premium package; plugin failures warn and preserve scanner findings.
- **Error handling**: Scanner failures raise `ToolError`; empty findings mean a completed scan. API helpers return `None`/`False` for delivery/authentication failures. The command layer owns exit codes (`1 > 3 > 4`; `2` is invalid usage).
- **Tests**: pytest + mock scanner execution (`subprocess.Popen`) and `httpx` as appropriate. Fixtures in `tests/fixtures/`.
