# Gerion CLI - Technical Specification

## 🎯 Purpose & Scope

**Gerion CLI** is a command-line interface tool for performing security scans on codebases. It integrates multiple security scanning tools (Gitleaks, Trivy) to detect secrets, vulnerable dependencies, and infrastructure misconfigurations, and can send results to the Gerion API Gateway for centralized management.

### Core Responsibilities
- **Security Scanning**: Execute secrets detection, SCA (Software Component Analysis), and IaC (Infrastructure as Code) scans
- **Tool Integration**: Orchestrate external security tools (Gitleaks, Trivy) in a unified interface
- **API Integration**: Authenticate and send scan results to Gerion API Gateway using M2M API keys
- **Output Generation**: Support multiple output formats (JSON, Markdown, SARIF) and console display
- **Metadata Collection**: Automatically extract Git repository metadata (branch, commit, author)

## 🏗️ Architecture Overview

### System Components
```
Gerion CLI → Security Tools (Gitleaks/Trivy) → Parse Results → API Gateway → Data API
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
- **Docker Native**: Single Docker image with all dependencies (Trivy, Gitleaks, CLI)
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
- **Trivy**: SCA (vulnerability scanning) and IaC (infrastructure misconfiguration) scanning

### Project Structure
```
gerion-cli/
├── gerion_cli/
│   ├── api/                    # API integration layer
│   │   ├── auth.py            # M2M API key authentication
│   │   └── client.py          # HTTP client for API Gateway
│   ├── commands/              # CLI command handlers
│   │   ├── secrets_scan.py   # Secrets scanning command
│   │   ├── sca_scan.py       # SCA scanning command
│   │   └── iac_scan.py       # IaC scanning command
│   ├── core/                  # Core functionality
│   │   ├── logging.py        # Logging configuration (Rich-based)
│   │   ├── metadata.py       # Git metadata extraction
│   │   └── types.py          # Custom types (SecretString)
│   ├── output/               # Output formatting
│   │   ├── formats.py        # File output (JSON, Markdown, SARIF)
│   │   └── tables.py         # Console table display
│   ├── tools/                # Security tool integration
│   │   ├── secrets.py        # Gitleaks integration
│   │   ├── sca.py            # Trivy SCA integration
│   │   ├── iac.py            # Trivy IaC integration
│   │   └── parser.py         # Tool output parsing
│   ├── utils/                # Utility functions
│   └── main.py               # CLI application entry point
├── Dockerfile                # Multi-stage Docker build
├── pyproject.toml           # Poetry configuration
├── requirements.txt         # Python dependencies
└── spec/
    └── plan.md              # This document
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
- **Tool**: Trivy filesystem scanner (vulnerability mode)
- **Output**: List of CVEs with affected packages and versions

### IaC Scan
```bash
gerion-cli iac-scan [CODE_PATH] [OPTIONS]
```
- **Purpose**: Detect misconfigurations in Infrastructure as Code files
- **Tool**: Trivy config scanner
- **Output**: List of IaC misconfigurations with severity and remediation

### Common Options
- `--api-url TEXT`: API Gateway URL (overrides `GERION_API_URL`)
- `--api-key TEXT`: M2M API key (overrides `GERION_API_KEY`, hidden input)
- `--client-id TEXT`: Client ID (overrides `GERION_CLIENT_ID`)
- `--output-file TEXT`: Save results to file (disables API sending)
- `--format [json|markdown|sarif]`: Output format for file saving
- `--log-level [debug|info|warning|error|critical]`: Logging verbosity

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
    'scan_type': str,               # Secrets, SCA, IaC
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
    'mitigated_on_build_id': str    # Build ID when mitigated
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
    'scan_type': str                # Secrets, SCA, IaC
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

### Trivy SCA Integration
- **Command**: `trivy fs --scanners vuln -f json --exit-code 0 -o <report_path> <code_path>`
- **Output Format**: JSON with `Results` array containing vulnerabilities
- **Parsing**: Extracts package information, CVE IDs, severity, and fixed versions
- **Finding ID**: SHA256 hash of `[target, vulnerability_id, package_id]`

### Trivy IaC Integration
- **Command**: `trivy config -f json -o <report_path> <code_path>`
- **Output Format**: JSON with `Results` array containing misconfigurations
- **Parsing**: Extracts misconfiguration ID, title, description, severity, and resolution
- **Finding ID**: SHA256 hash of `[file_path, id_str, title]`

## 📊 Output Formats

### Console Output
- **Rich Tables**: Color-coded tables sorted by severity
- **Panels**: Summary panels with scan metadata
- **Logging**: Structured logging with Rich formatting (debug, info, warning, error, success)

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
1. **Builder Stage**: Downloads and installs Trivy and Gitleaks binaries
2. **CLI Builder Stage**: Builds Python CLI using PyInstaller
3. **Final Stage**: Combines all binaries in minimal Alpine image

### Docker Image Features
- **Single Binary**: CLI compiled to single executable via PyInstaller
- **All Tools Included**: Trivy and Gitleaks pre-installed
- **Non-Root User**: Runs as `gerion` user (UID 1000) for security
- **Volume Mounts**: `/code` for code to scan, `/output` for output files

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

## 🧪 Testing Strategy

### Test Categories
1. **Unit Tests**: Tool output parsing, metadata extraction
2. **Integration Tests**: API authentication and submission
3. **End-to-End Tests**: Full scan workflow with mock API
4. **Docker Tests**: Container build and execution

### Test Data Requirements
- **Mock Tool Output**: Sample Gitleaks and Trivy JSON outputs
- **Mock API Responses**: Authentication and findings submission responses
- **Test Repositories**: Sample codebases with known vulnerabilities

## 📊 Code Organization

### Command Pattern
Each scan type (secrets, SCA, IaC) follows the same pattern:
1. **Metadata Collection**: Extract Git repository information
2. **Tool Execution**: Run external security tool
3. **Output Parsing**: Parse tool JSON output to findings
4. **Result Processing**: Format findings and metadata
5. **Output**: Send to API or save to file

### Error Handling
- **Tool Failures**: Graceful handling of tool execution errors
- **API Failures**: Fallback to console output if API submission fails
- **Validation Errors**: Clear error messages for invalid inputs

### Logging Strategy
- **Structured Logging**: Rich-based logging with color coding
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
# Run all scan types
gerion-cli secrets-scan . --output-file secrets.json
gerion-cli sca-scan . --output-file sca.json
gerion-cli iac-scan . --output-file iac.json
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

