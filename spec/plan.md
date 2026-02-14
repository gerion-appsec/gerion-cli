# Gerion CLI - Technical Specification

## 🎯 Purpose & Scope

**Gerion CLI** is a command-line interface tool for performing security scans on codebases. It integrates multiple security scanning tools (Gitleaks, OSV-Scanner, KICS, Opengrep) to detect secrets, vulnerable dependencies, and infrastructure misconfigurations, and can send results to the Gerion API Gateway for centralized management.

### Core Responsibilities
- **Security Scanning**: Execute SAST (Static Analysis), Secrets detection, SCA (Software Component Analysis), and IaC (Infrastructure as Code) scans
- **Tool Integration**: Orchestrate external security tools (Opengrep, Gitleaks, OSV-Scanner, KICS) in a unified interface
- **API Integration**: Authenticate and send scan results to Gerion API Gateway using M2M API keys
- **Output Generation**: Support multiple output formats (JSON, Markdown, SARIF) and console display
- **Metadata Collection**: Automatically extract Git repository metadata (branch, commit, author)

## 🏗️ Architecture Overview

### System Components
```
Gerion CLI → Security Tools (Gitleaks/OSV/KICS/Opengrep) → Parse Results → API Gateway → Data API
                ↓
         Local File Output (optional)
```

### Authentication Flow
1. **M2M Authentication**: CLI uses API key to authenticate with API Gateway
2. **JWT Token**: API Gateway returns RS256 JWT access token
3. **API Calls**: CLI uses JWT token for subsequent API requests (findings submission)

### Key Design Principles
- **Tool Agnostic**: Abstract security tool execution behind unified interface
- **Flexible Output**: Support both API submission and local file output
- **CI/CD Ready**: Designed for integration in CI/CD pipelines with environment variable support
- **Docker Native**: Single Docker image with all dependencies
- **Metadata Aware**: Automatic Git metadata extraction for traceability

## 🔧 Technical Stack

### Core Technologies
- **Framework**: Typer 0.15.2 (CLI framework built on Click)
- **Python**: 3.12+
- **HTTP Client**: httpx 0.27.0 (async HTTP client)
- **Rich Output**: rich 13.7.0 (beautiful terminal output)
- **Data Validation**: pydantic 2.6.0 (data models and validation)
- **Git Integration**: GitPython 3.1.44 (repository metadata extraction)
- **Package Management**: Poetry (dependency management)

### External Tools
- **Gitleaks**: Secrets detection in code repositories
- **OSV-Scanner**: SCA (vulnerability scanning)
- **KICS**: IaC (infrastructure misconfiguration) scanning
- **Opengrep**: SAST (Static Application Security Testing) for code patterns and bugs

### Project Structure
```
gerion-cli/
├── gerion_cli/
│   ├── api/                    # API integration layer
│   │   ├── auth.py            # M2M API key authentication
│   │   └── client.py          # HTTP client for API Gateway
│   ├── commands/              # CLI command handlers
│   │   ├── base.py           # Shared scan orchestration (run_scan)
│   │   ├── secrets_scan.py   # Secrets scanning command (thin wrapper)
│   │   ├── sca_scan.py       # SCA scanning command (thin wrapper)
│   │   ├── iac_scan.py       # IaC scanning command (thin wrapper)
│   │   ├── sast_scan.py      # SAST scanning command (thin wrapper)
│   │   ├── scan_all.py       # Runs all 4 scans sequentially
│   │   └── report.py         # Report generation command
│   ├── core/                  # Core functionality
│   │   ├── config.py         # __version__, CLIENT_ID
│   │   ├── logging.py        # GerionLogger (Rich-based, stderr), LogLevel enum
│   │   ├── metadata.py       # Git metadata extraction + CI/CD detection
│   │   └── types.py          # SecretString wrapper, OutputFormat enum (json, markdown, sarif, table)
│   ├── output/               # Output formatting
│   │   ├── formats.py        # File/stdout output (JSON, Markdown, SARIF) + content generators
│   │   └── tables.py         # Console table display (own stdout Console)
│   ├── tools/                # Security tool integration
│   │   ├── secrets.py        # Gitleaks integration
│   │   ├── sca.py            # OSV-Scanner SCA integration
│   │   ├── iac.py            # KICS IaC integration
│   │   ├── sast.py           # Opengrep SAST integration
│   │   └── parser.py         # Tool output parsing
│   ├── utils/                # Utility functions
│   └── main.py               # CLI application entry point
├── tests/                    # Unit tests + fixtures
├── Dockerfile                # Multi-stage Docker build
├── pyproject.toml           # Poetry configuration
├── requirements.txt         # Python dependencies
└── spec/
    ├── plan.md              # This document
    ├── project_context.md   # LLM project context
    ├── agent_rules.md       # LLM agent rules
    ├── backlog.md           # Development backlog (all tiers T1-T5 complete)
    └── tool_output_audit.md # #9 audit results
```

## 🔐 Authentication System

### M2M API Key Authentication

The CLI uses Machine-to-Machine (M2M) API key authentication to communicate with the API Gateway.

#### Authentication Flow
1. **API Key Provisioning**: User creates API key via web interface or API (requires user JWT)
2. **CLI Authentication**: CLI sends API key to API Gateway `/api/v1/auth/m2m/authenticate`
3. **JWT Token**: API Gateway validates API key and returns RS256 JWT access token
4. **API Calls**: CLI uses JWT token in `Authorization: Bearer <token>` header for API requests

#### API Key Format
- **Header Options**: 
  - `Authorization: Bearer <api_key>` (recommended, OAuth2 standard)
  - `X-API-Key: <api_key>` (alternative)
- **Request Body**: `{"client_id": "gerion-cli-{version}"}` (e.g., `{"client_id": "gerion-cli-0.1.0"}`)
- **Response**: `{"access_token": "...", "token_type": "bearer", "expires_in": 1800, "client_id": "...", "api_key_id": "..."}`

#### Environment Variables
- `GERION_API_URL`: API Gateway base URL (e.g., `https://api.gerion.com`)
- `GERION_API_KEY`: M2M API key for authentication
- `GERION_CLIENT_ID`: Client identifier (optional, default: `gerion-cli-{version}`, e.g., `gerion-cli-0.1.0`)

**Note**: The `CLIENT_ID` is automatically set based on the CLI version (`gerion-cli-{version}`) to allow the API Gateway to identify which version of the CLI is making requests. This is defined in `gerion_cli/core/config.py` and should not be changed unless necessary.

## 📡 CLI Commands

### SAST Scan
```bash
gerion-cli sast-scan [CODE_PATH] [OPTIONS]
```
- **Purpose**: Detect security vulnerabilities and code quality issues
- **Tool**: Opengrep
- **Output**: List of findings with detailed message and severity

### Secrets Scan
```bash
gerion-cli secrets-scan [CODE_PATH] [OPTIONS]
```
- **Purpose**: Detect hardcoded secrets (API keys, passwords, tokens) in code
- **Tool**: Gitleaks
- **Output**: List of secret findings with file paths and line numbers

### SCA Scan
```bash
gerion-cli sca-scan [CODE_PATH] [OPTIONS]
```
- **Purpose**: Detect vulnerable dependencies in project dependencies
- **Tool**: OSV-Scanner
- **Output**: List of CVEs with affected packages and versions

### IaC Scan
```bash
gerion-cli iac-scan [CODE_PATH] [OPTIONS]
```
- **Purpose**: Detect misconfigurations in Infrastructure as Code files
- **Tool**: KICS
- **Output**: List of IaC misconfigurations with severity and remediation

### Scan All
```bash
gerion-cli scan-all [CODE_PATH] [OPTIONS]
```
- **Purpose**: Run all 4 scan types (Secrets, SCA, IaC, SAST) sequentially
- **Tools**: Gitleaks, OSV-Scanner, KICS, Opengrep
- **Output**: When `--output-file` or `--format` is set, individual scans are suppressed and aggregated output is handled at the end. Otherwise, each scan outputs independently (API or table)

### Common Options
- `--api-url TEXT`: API Gateway URL (overrides `GERION_API_URL`)
- `--api-key TEXT`: M2M API key (overrides `GERION_API_KEY`, hidden input)
- `--client-id TEXT`: Client ID (overrides `GERION_CLIENT_ID`)
- `--output-file TEXT`: Save results to file (suppresses API and console output)
- `--format [json|markdown|sarif|table]`: Output format for file saving or stdout (default: None — falls through to API or table)
- `--timeout INT`: Tool execution timeout in seconds (default: 180)
- `--log-level [debug|info|warning|error|critical]`: Logging verbosity
- `--queries-path TEXT`: (IaC only) Path to KICS queries directory

## 🗃️ Data Models

### Finding Model
```python
{
    'finding_id': str,              # Unique identifier (SHA256 hash)
    'title': str,                   # Finding title
    'description': str,             # Detailed description
    'mitigation': str,              # Remediation guidance
    'severity': str,                # Critical, High, Medium, Low, Info
    'security_scope': str,          # Code, IaC
    'scan_type': str,               # Secrets, SCA, IaC, SAST
    'repository_name': str,         # Git repository name
    'branch_name': str,             # Git branch name
    'build_id': str,                # CI/CD build identifier
    'code_path': str,               # Code path scanned
    'commit_hash': str,             # Git commit SHA
    'commit_author': str,           # Git commit author
    'file_path': str,               # File where finding was detected
    'line_number': int,             # Line number in file
    'component_name': str,          # (SCA only) Package name
    'component_version': str,       # (SCA only) Package version
    'component_fix': str,           # (SCA only) Fixed version
    'cwe': List[str],               # CWE identifiers
    'cve': str,                     # (SCA only) CVE identifier
    'active': bool,                 # Finding status
    'mitigated': bool,              # Mitigation status
    'false_positive': bool,         # False positive flag
    'creation_date': str,           # ISO timestamp
    'last_update_date': str,        # ISO timestamp
    'mitigated_on_build_id': str,   # Build ID when mitigated
    # Premium Fields (Optional)
    'trace': dict,                  # Trace graph (nodes/edges)
    'reachability': str,            # REACHABLE, UNREACHABLE, UNKNOWN
    'risk_score': float,            # Calculated risk score
    'confidence': str               # LOW, MEDIUM, HIGH
}
```

### Metadata Model
```python
{
    'repository_name': str,         # Git repository name
    'branch_name': str,             # Git branch name
    'build_id': str,                # CI/CD build identifier
    'code_path': str,               # Code path scanned
    'commit_hash': str,             # Git commit SHA
    'commit_author': str,           # Git commit author
    'scan_type': str,               # Secrets, SCA, IaC, SAST
    'scan_duration': float          # Seconds elapsed during tool execution
}
```

### API Request Format
```python
{
    "findings_data": {
        "metadata": Metadata,
        "findings": List[Finding]
    }
}
```

## 🔍 Tool Integration
 
 ### Gitleaks Integration (Secrets)
 - **Command**: `gitleaks dir <code_path> --exit-code 0 -f json -r <report_path>`
 - **Output Format**: JSON array of secret findings
 - **Parsing**: Extracts file path, line number, rule ID, and secret match
 - **Finding ID**: SHA256 hash of `[file_path, match_text, rule_id]`
 
 ### OSV-Scanner Integration (SCA)
 - **Command**: `osv-scanner scan --format json --output <report_path> <code_path>`
 - **Output Format**: JSON with `results` array containing packages and vulnerabilities
 - **Parsing**: Extracts package information, CVE IDs, severity, and fixed versions
 - **Finding ID**: SHA256 hash of `[target, vulnerability_id, package_name, package_version]`
 
 ### KICS Integration (IaC)
 - **Command**: `kics scan --path <code_path> --output-path <dir> --report-formats json ...`
 - **Output Format**: JSON with `queries` array containing misconfigurations
 - **Parsing**: Extracts misconfiguration ID, title, description, severity, and resolution
 - **Finding ID**: SHA256 hash of `[file_path, id_str, line]`

## 📊 Output Formats

### Console Output
- **Rich Tables**: Color-coded tables sorted by severity (stdout)
- **Panels**: Summary panels with scan metadata (stderr)
- **Logging**: Structured logging with Rich formatting to stderr (debug, info, warning, error, success)
- **Stdout/stderr separation**: Logging and panels go to stderr, formatted output and tables go to stdout — enables clean piping (`gerion-cli sast-scan --format json | jq`)

### JSON Output
- **Format**: Standard JSON with findings array and metadata
- **Use Case**: Programmatic processing, CI/CD integration

### Markdown Output
- **Format**: Human-readable Markdown report
- **Sections**: Summary, findings table, detailed findings
- **Use Case**: Documentation, GitHub/GitLab merge requests

### SARIF Output
- **Format**: SARIF 2.1.0 standard format
- **Use Case**: GitHub Security, Azure DevOps, other SARIF-compatible tools

## 🐳 Docker Integration

### Multi-Stage Build
1. **Builder Stage**: Downloads and installs Opengrep, OSV-Scanner, KICS, and Gitleaks binaries
2. **CLI Builder Stage**: Builds Python CLI using PyInstaller
3. **Final Stage**: Combines all binaries in minimal Debian slim image

### Docker Image Features
- **Single Binary**: CLI compiled to single executable via PyInstaller
- **All Tools Included**: Opengrep, OSV-Scanner, KICS, and Gitleaks pre-installed
- **Non-Root User**: Runs as `gerion` user (UID 1000) for security
- **Volume Mounts**: `/code` for code to scan, `/output` for output files

### Open Core Architecture
- **Core Image**: Builds from `gerion-cli` (Open Source).
- **Premium Image**: Builds by overlaying `gerion-cli-premium` on top of Core.
    - Adds **Trace Graphs**, **Deep Reachability**, and **Risk Scoring**.
    - Build Context: Requires parent directory containing both repos.
    - Command: `docker build -f gerion-cli-premium/Dockerfile.premium -t gerion-cli-premium .`

### Usage
```bash
docker run --rm -v "$PWD:/code" \
  -e GERION_API_URL=https://api.gerion.com \
  -e GERION_API_KEY=your-api-key \
  gerion-cli secrets-scan /code
```

## 🔒 Security Considerations

### Implemented Security Measures
- **Secret Masking**: API keys and secrets never printed in logs (SecretString wrapper)
- **Non-Root Execution**: Docker container runs as non-root user
- **Secure Storage**: API keys stored as environment variables, not in code
- **HTTPS Only**: All API communication over HTTPS
- **Token Expiration**: JWT tokens have expiration time (30 minutes default)

### Security Best Practices
- **API Key Rotation**: Regularly rotate API keys via web interface
- **Environment Variables**: Use environment variables for credentials in CI/CD
- **Output Sanitization**: Markdown output sanitizes control characters
- **Error Handling**: Limited error details to prevent information leakage

## 🧪 Testing

### Current Coverage
- `test_parser.py` — All 4 parsers with real fixture data (gitleaks, osv, opengrep, kics)
- `test_metadata.py` — Git metadata + GitHub Actions env vars + manual overrides
- `test_finding.py` — `generate_finding_template()`, `generate_unique_id()`, `redact_text()`
- `test_auth.py` — M2M auth success, 401, network error, invalid JSON
- `test_output.py` — JSON, Markdown, SARIF serialization via `save_to_file()`

### Test Infrastructure
- **Fixtures**: `tests/fixtures/` with real tool JSON outputs (trimmed for size)
- **Shared fixtures**: `conftest.py` with `mock_metadata`, `load_fixture`, `fixtures_dir`
- **Mocking**: `unittest.mock.patch` for `subprocess.run`, `httpx.post`, `git.Repo`

## 📊 Code Organization

### Command Pattern
All scan commands are thin wrappers that call `commands/base.py:run_scan()`:
1. **Setup**: Log level, API key conversion, client ID defaulting
2. **Metadata Collection**: Extract Git repository information
3. **Tool Execution**: Run external security tool with duration tracking
4. **Output Parsing**: Parse tool JSON output to findings
5. **Summary**: Display panel with repo, branch, findings count, duration (stderr)
6. **Output routing** (mutually exclusive priority):
   - `--output-file` → save to file (format inferred from extension if not explicit)
   - `--format` → print to stdout in chosen format
   - API creds → send to API (fallback to table on failure)
   - fallback → display findings table in console

### Error Handling
- **Tool Failures**: Graceful handling via `try/except` in `base.py`; `typer.Exit(1)` on `None` returns
- **API Failures**: Fallback to console output if API submission fails
- **Validation Errors**: Clear error messages for invalid inputs

### Logging Strategy
- **Structured Logging**: Rich-based logging with color coding (all layers including tool runners)
- **Log Levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Debug Mode**: Detailed logging for troubleshooting (tool commands, API requests)

## 🚀 Deployment

### Installation Methods

#### Poetry (Development)
```bash
git clone <repository>
cd gerion-cli
poetry install
poetry run gerion-cli --help
```

#### Docker (Production)
```bash
docker build -t gerion-cli .
docker run --rm gerion-cli --help
```

#### PyInstaller (Standalone Binary)
```bash
poetry install
poetry run pyinstaller --onefile gerion_cli/main.py
```

### CI/CD Integration

#### GitHub Actions Example
```yaml
- name: Run Gerion Secrets Scan
  run: |
    docker run --rm -v "$PWD:/code" \
      -e GERION_API_URL=${{ secrets.GERION_API_URL }} \
      -e GERION_API_KEY=${{ secrets.GERION_API_KEY }} \
      gerion-cli secrets-scan /code
```

#### GitLab CI Example
```yaml
gerion-scan:
  image: gerion-cli:latest
  script:
    - gerion-cli secrets-scan . --api-url $GERION_API_URL --api-key $GERION_API_KEY
```

## 🔄 Workflow Examples

### Local Development Scan
```bash
# Scan current directory for secrets
gerion-cli secrets-scan . \
  --api-url https://api.gerion.com \
  --api-key your-api-key \
  --log-level debug
```

### CI/CD Pipeline Scan
```bash
# Scan and save to file (no API submission)
gerion-cli sca-scan . \
  --output-file scan-results.json \
  --format json
```

### Multi-Scan Workflow
```bash
# Run all scan types at once
gerion-cli scan-all . --output-file results.json

# Or individually
gerion-cli secrets-scan . --output-file secrets.json
gerion-cli sca-scan . --output-file sca.json
gerion-cli iac-scan . --output-file iac.json
gerion-cli sast-scan . --output-file sast.json
```

## 📝 Implementation Guidelines for AI Agents

When working on this project, AI agents should:

### Code Patterns
- **Use Typer**: All CLI commands use Typer for argument parsing
- **Secret Handling**: Always use `SecretString` wrapper for sensitive data
- **Error Handling**: Use Rich logging functions (error, warning, success)
- **Metadata**: Always collect Git metadata before scanning

### API Integration
- **Authentication**: Use M2M API key authentication (not user credentials)
- **Token Management**: Store JWT token in memory, re-authenticate on expiration
- **Error Handling**: Handle 401 errors by re-authenticating

### Tool Integration
- **Temporary Files**: Always clean up temporary report files
- **Exit Codes**: Use `--exit-code 0` to prevent tool failures from stopping CLI
- **Output Parsing**: Handle missing fields gracefully with fallback values

### Testing
- **Mock Tools**: Mock external tool execution in tests
- **Mock API**: Use httpx test client for API integration tests
- **Test Data**: Use sample tool outputs from `tests/` directory

---

**Gerion CLI** - Unified command-line interface for security scanning with API Gateway integration and multi-format output support.

