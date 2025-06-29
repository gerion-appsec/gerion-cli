# Gerion CLI

A powerful command-line interface for performing security scans on your codebase. The Gerion CLI allows you to scan for secrets and perform software component analysis (SCA) with ease.

## Features

- **Secrets Scan**: Detect sensitive information such as API keys, passwords, and other secrets in your code.
- **Software Component Analysis (SCA)**: Identify vulnerabilities in your project's dependencies.
- **API Integration**: Send scan results to a specified API for further processing or storage.
- **Multiple Output Formats**: Save scan results in JSON, Markdown, or SARIF formats.
- **CI/CD Integration**: Automatic detection of GitHub Actions, Jenkins, and GitLab CI environments.
- **Beautiful Logging**: Rich, formatted output with different log levels and progress indicators.
- **Secure Credentials**: Uses SecretStr to protect sensitive information in logs.
- **Well-Organized Architecture**: Clean, modular codebase with clear separation of concerns.
- **Smart Repository Detection**: Automatically detects repository metadata from Git remotes (supports GitHub, GitLab, Bitbucket, and more).
- **Docker Support**: Complete Docker image with all security tools included.

## Installation

### From Source

Clone this repository and install it locally:

```sh
git clone https://github.com/your-repo/gerion-cli.git
cd gerion-cli
pip install -r requirements.txt
```

### Using Poetry (Recommended for Development)

```sh
git clone https://github.com/your-repo/gerion-cli.git
cd gerion-cli
poetry install
```

### Using Docker (Recommended for Production)

The Docker image includes all necessary security tools (Trivy and Gitleaks):

```sh
# Build the image
docker build -t gerion-cli .

# Or use the helper script
./scripts/docker-run.sh --build
```

## Configuration

### Environment Variables

For security, API credentials can be configured using environment variables. Typer will automatically read these variables:

```sh
export GERION_API_URL="https://api.gerion.com"
export GERION_CLIENT_ID="your-client-id"
export GERION_CLIENT_SECRET="your-client-secret"
```

**Environment Variables:**
- `GERION_API_URL`: API URL for sending results
- `GERION_CLIENT_ID`: Client ID for API authentication
- `GERION_CLIENT_SECRET`: Client secret for API authentication

**Note:** Command-line parameters will override environment variables if both are provided.

## Usage

### Default Behavior

By default, Gerion CLI will attempt to send results to the API if credentials are provided via environment variables or parameters. If no credentials are available, results will be displayed in the console.

### Logging Levels

The CLI supports different logging levels to control the verbosity of output:

- `debug`: Detailed debug information
- `info`: General information (default)
- `warning`: Warning messages
- `error`: Error messages only
- `critical`: Critical errors only

### Output Formats

When saving results to a file, you can specify the output format:

- `json`: JSON format (default) - Structured data for programmatic processing
- `markdown`: Markdown format - Human-readable report with tables and formatting
- `sarif`: SARIF format - Standard format for static analysis results

### Secrets Scan

To perform a secrets scan on your codebase, run the following command:

```sh
# Using Python directly
python -m gerion_cli.main secrets-scan [OPTIONS] [CODE_PATH]

# Using Docker
docker run --rm -v "$PWD:/code" gerion-cli secrets-scan /code

# Using the helper script
./scripts/docker-run.sh --type secrets --path ./src
```

**Options:**

- `--api-url TEXT`: API URL for sending results (reads from GERION_API_URL env var if not provided).
- `--client-id TEXT`: Client ID for API authentication (reads from GERION_CLIENT_ID env var if not provided).
- `--client-secret TEXT`: Client secret for API authentication (reads from GERION_CLIENT_SECRET env var if not provided).
- `--output-file TEXT`: Save results to a file (disables API sending).
- `--format [json|markdown|sarif]`: Output format for file saving (default: json).
- `--log-level [debug|info|warning|error|critical]`: Set the logging level (default: info).

**Examples:**

```sh
# Using environment variables (recommended for security)
export GERION_API_URL="https://api.gerion.com"
export GERION_CLIENT_ID="your-client-id"
export GERION_CLIENT_SECRET="your-client-secret"
python -m gerion_cli.main secrets-scan /path/to/code

# Using command-line parameters with debug logging
python -m gerion_cli.main secrets-scan --api-url https://api.gerion.com --client-id your-client-id --client-secret your-client-secret --log-level debug /path/to/code

# Save results to JSON file (default format)
python -m gerion_cli.main secrets-scan --output-file scan_results.json /path/to/code

# Save results to Markdown file
python -m gerion_cli.main secrets-scan --output-file scan_report.md --format markdown /path/to/code

# Save results to SARIF file
python -m gerion_cli.main secrets-scan --output-file scan_results.sarif --format sarif /path/to/code

# Display results in console only (no credentials provided)
python -m gerion_cli.main secrets-scan /path/to/code

# Using Docker
docker run --rm -v "$PWD:/code" gerion-cli secrets-scan /code

# Using Docker with file output
docker run --rm -v "$PWD:/code" -v "$PWD:/output" gerion-cli secrets-scan --output-file /output/results.md --format markdown /code
```

### Software Component Analysis (SCA)

To perform software component analysis on your codebase, run the following command:

```sh
# Using Python directly
python -m gerion_cli.main sca-scan [OPTIONS] [CODE_PATH]

# Using Docker
docker run --rm -v "$PWD:/code" gerion-cli sca-scan /code

# Using the helper script
./scripts/docker-run.sh --type sca --path ./src
```

**Options:**

- `--api-url TEXT`: API URL for sending results (reads from GERION_API_URL env var if not provided).
- `--client-id TEXT`: Client ID for API authentication (reads from GERION_CLIENT_ID env var if not provided).
- `--client-secret TEXT`: Client secret for API authentication (reads from GERION_CLIENT_SECRET env var if not provided).
- `--output-file TEXT`: Save results to a file (disables API sending).
- `--format [json|markdown|sarif]`: Output format for file saving (default: json).
- `--log-level [debug|info|warning|error|critical]`: Set the logging level (default: info).

**Examples:**

```sh
# Using environment variables (recommended for security)
export GERION_API_URL="https://api.gerion.com"
export GERION_CLIENT_ID="your-client-id"
export GERION_CLIENT_SECRET="your-client-secret"
python -m gerion_cli.main sca-scan /path/to/code

# Using command-line parameters with debug logging
python -m gerion_cli.main sca-scan --api-url https://api.gerion.com --client-id your-client-id --client-secret your-client-secret --log-level debug /path/to/code

# Save results to JSON file (default format)
python -m gerion_cli.main sca-scan --output-file scan_results.json /path/to/code

# Save results to Markdown file
python -m gerion_cli.main sca-scan --output-file scan_report.md --format markdown /path/to/code

# Save results to SARIF file
python -m gerion_cli.main sca-scan --output-file scan_results.sarif --format sarif /path/to/code

# Display results in console only (no credentials provided)
python -m gerion_cli.main sca-scan /path/to/code

# Using Docker
docker run --rm -v "$PWD:/code" gerion-cli sca-scan /code

# Using Docker with file output
docker run --rm -v "$PWD:/code" -v "$PWD:/output" gerion-cli sca-scan --output-file /output/results.json --format json /code
```

## Output Format Examples

### Console Output

The CLI displays results in clean, formatted tables:

**Secrets Scan:**
```
┌──────────┬──────────────────────────────────────────────────┬───────────────────┐
│ Severity │ Title                                            │ File:Line         │
├──────────┼──────────────────────────────────────────────────┼───────────────────┤
│ 🔴 High  │ Hard coded secret: AWS_ACCESS_KEY_ID            │ config.py:42     │
└──────────┴──────────────────────────────────────────────────┴───────────────────┘
```

**SCA Scan:**
```
┌──────────┬───────────────┬────────────────────────────────────┬───────────────────┐
│ Severity │ CVE           │ Component                           │ File              │
├──────────┼───────────────┼────────────────────────────────────┼───────────────────┤
│ 🔴 High  │ CVE-2021-33503│ requests 2.25.1                    │ requirements.txt  │
└──────────┴───────────────┴────────────────────────────────────┴───────────────────┘
```

### JSON Format
```json
{
    "metadata": {
        "repository_name": "my-repo",
        "branch_name": "main",
        "commit_hash": "abc123...",
        "build_id": "123"
    },
    "findings": [
        {
            "finding_id": "abc123...",
            "title": "Hard coded secret: AWS_ACCESS_KEY_ID",
            "severity": "High",
            "file_path": "config.py",
            "line_number": 42,
            "description": "AWS access key found in code"
        }
    ]
}
```

### Markdown Format
```markdown
# Secrets Scan Report

## Scan Summary

- **Repository**: my-repo
- **Branch**: main
- **Commit**: abc123...
- **Scan Date**: 2024-01-15 10:30:00
- **Total Findings**: 1

## Findings

| Severity | Title | File:Line |
|----------|-------|-----------|
| 🔴 High | Hard coded secret: AWS_ACCESS_KEY_ID | `config.py:42` |

## Detailed Findings

### 🔴 Hard coded secret: AWS_ACCESS_KEY_ID

- **Severity**: High
- **File**: `config.py:42`
- **Description**: AWS access key found in code
- **Mitigation**: Remove the secret from the code and rotate it

---
```

### SARIF Format
```json
{
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Gerion Secrets Scanner",
                    "version": "1.0.0"
                }
            },
            "results": [
                {
                    "ruleId": "abc123...",
                    "level": "error",
                    "message": {
                        "text": "AWS access key found in code"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "config.py"
                                },
                                "region": {
                                    "startLine": 42,
                                    "startColumn": 1
                                }
                            }
                        }
                    ]
                }
            ]
        }
    ]
}
```

## Project Structure

The Gerion CLI follows a clean, modular architecture:

```
gerion_cli/
├── main.py                    # Main entry point
├── commands/                  # CLI commands
│   ├── secrets_scan.py       # Secrets scanning command
│   └── sca_scan.py           # SCA scanning command
├── core/                      # Core functionality
│   ├── logging.py            # Logging and enums
│   ├── types.py              # Custom types (SecretString)
│   └── metadata.py           # Repository metadata handling
├── tools/                     # Security tools integration
│   ├── sca.py               # Trivy integration
│   ├── secrets.py           # Gitleaks integration
│   └── parser.py            # Results parsing
├── api/                       # API integration
│   ├── client.py            # HTTP client
│   └── auth.py              # JWT authentication
├── output/                    # Output generation
│   ├── formats.py           # File formats (JSON, Markdown, SARIF)
│   └── tables.py            # Console tables
└── utils/                     # General utilities
    └── __init__.py
```

## Docker Usage

### Building the Docker Image

You can build the Docker image locally with all necessary security tools included:

```sh
# Build the image with default tool versions
docker build -t gerion-cli .

# Build with specific tool versions
docker build \
  --build-arg TRIVY_VERSION=0.61.0 \
  --build-arg GITLEAKS_VERSION=8.24.2 \
  -t gerion-cli .
```

### Running with Docker

The Docker image includes Trivy and Gitleaks, so you don't need to install them separately.

#### Basic Usage

```sh
# Mount your code directory and run a scan
docker run --rm -v "$PWD:/code" gerion-cli secrets-scan /code
docker run --rm -v "$PWD:/code" gerion-cli sca-scan /code
```

#### With API Integration

```sh
# Using environment variables (recommended for security)
docker run --rm \
  -e GERION_API_URL="https://api.gerion.com" \
  -e GERION_CLIENT_ID="your-client-id" \
  -e GERION_CLIENT_SECRET="your-client-secret" \
  -v "$PWD:/code" \
  gerion-cli secrets-scan /code

# Using command-line parameters
docker run --rm \
  -v "$PWD:/code" \
  gerion-cli secrets-scan \
  --api-url https://api.gerion.com \
  --client-id your-client-id \
  --client-secret your-client-secret \
  /code
```

#### Saving Results to Files

```sh
# Save results to different formats
docker run --rm \
  -v "$PWD:/code" \
  -v "$PWD:/output" \
  gerion-cli secrets-scan \
  --output-file /output/results.md \
  --format markdown \
  /code
```

### Troubleshooting Rich Display Issues

If you experience issues with table formatting or colors in Docker, try these solutions:

#### Option 1: Use Interactive Terminal

```sh
# Run with interactive terminal for better display
docker run --rm -it -v "$PWD:/code" gerion-cli secrets-scan /code
```

#### Option 2: Set Terminal Environment Variables

```sh
# Set terminal variables for better compatibility
docker run --rm \
  -e TERM=xterm-256color \
  -e FORCE_COLOR=1 \
  -e PYTHONUNBUFFERED=1 \
  -v "$PWD:/code" \
  gerion-cli secrets-scan /code
```

#### Option 3: Use the Helper Script with Interactive Mode

```sh
# The helper script automatically sets the correct environment variables
./scripts/docker-run.sh --type secrets --interactive
```

### Docker Helper Script

For convenience, a helper script is provided to simplify Docker usage:

```sh
# Make the script executable
chmod +x scripts/docker-run.sh

# Basic usage
./scripts/docker-run.sh --type secrets --path ./src

# Save results to file
./scripts/docker-run.sh --type sca --output results.json --format json

# Run with debug logging
./scripts/docker-run.sh --type secrets --log-level debug

# Run with interactive terminal for better display
./scripts/docker-run.sh --type secrets --interactive

# Build image and run
./scripts/docker-run.sh --type secrets --build

# Show help
./scripts/docker-run.sh --help
```

The script automatically:
- Checks if Docker is available
- Builds the image if it doesn't exist
- Handles volume mounting and environment variables
- Passes through CI/CD environment variables
- Sets proper terminal environment variables for Rich
- Provides colored output and error handling

### Docker Compose

You can also use Docker Compose for more complex setups:

```sh
# Create output directory
mkdir -p output

# Run secrets scan (sends to API if credentials provided)
docker-compose --profile secrets up --build

# Run SCA scan (sends to API if credentials provided)
docker-compose --profile sca up --build

# Run secrets scan and save to file
docker-compose --profile secrets-file up --build

# Run SCA scan and save to file
docker-compose --profile sca-file up --build
```

## Development

### Contributing

We welcome contributions from the community! To get started:

1. Fork this repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them with descriptive messages.
4. Push your changes to your forked repository.
5. Submit a pull request.

### Requirements

- Python 3.12 or higher
- Poetry (for dependency management)
- Typer
- GitPython
- HTTPX
- Rich (for beautiful output)
- Pydantic (for SecretStr and data validation)
- Trivy (for SCA scans)
- Gitleaks (for secrets scans)

### Setup Development Environment

1. Clone the repository:

    ```sh
    git clone https://github.com/your-repo/gerion-cli.git
    cd gerion-cli
    ```

2. Install dependencies:

    ```sh
    # Using Poetry (recommended)
    poetry install
    
    # Or using pip
    pip install -r requirements.txt
    ```

3. Install security tools (Trivy and Gitleaks) or use the Docker image.

4. Set up environment variables for testing:

    ```sh
    export GERION_API_URL="https://api.gerion.com"
    export GERION_CLIENT_ID="your-client-id"
    export GERION_CLIENT_SECRET="your-client-secret"
    ```

5. Run the CLI locally:

    ```sh
    # Using Poetry
    poetry run python -m gerion_cli.main secrets-scan /path/to/code
    poetry run python -m gerion_cli.main sca-scan /path/to/code
    
    # Or using Python directly
    python -m gerion_cli.main secrets-scan /path/to/code
    python -m gerion_cli.main sca-scan /path/to/code
    ```

### Testing

Run the Docker test suite to verify everything works:

```sh
# Run comprehensive tests
./scripts/test-docker.sh

# Clean up test artifacts
./scripts/test-docker.sh --clean
```

### Architecture Principles

- **Separation of Concerns**: Each module has a specific responsibility
- **Clean Imports**: Uses absolute imports for better maintainability
- **Modular Design**: Easy to extend with new tools or output formats
- **Type Safety**: Uses type hints and Pydantic for data validation
- **Security First**: Secure handling of credentials and sensitive data
- **Robust Parsing**: Handles different output formats from security tools gracefully

## License

This project is licensed under the Apache2.0 License. See the [LICENSE](LICENSE) file for more details.

## Acknowledgments

We would like to thank all contributors and users who have helped make this tool better.

---

Feel free to reach out if you have any questions or need further assistance!