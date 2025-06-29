# Gerion CLI

A powerful command-line interface for performing security scans on your codebase. The Gerion CLI allows you to scan for secrets and perform software component analysis (SCA) with ease.

## Features

- **Secrets Scan**: Detect sensitive information such as API keys, passwords, and other secrets in your code.
- **Software Component Analysis (SCA)**: Identify vulnerabilities in your project's dependencies.
- **API Integration**: Send scan results to a specified API for further processing or storage.
- **Multiple Output Formats**: Save scan results in JSON, Markdown, or SARIF formats.
- **JSON Output**: Save scan results to a JSON file for easy integration with other tools.
- **CI/CD Integration**: Automatic detection of GitHub Actions, Jenkins, and GitLab CI environments.
- **Beautiful Logging**: Rich, formatted output with different log levels and progress indicators.
- **Secure Credentials**: Uses SecretStr to protect sensitive information in logs.

## Installation

To install the Gerion CLI, you can use pip:

```sh
pip install gerion-cli
```

Alternatively, you can clone this repository and install it locally:

```sh
git clone https://github.com/your-repo/gerion-cli.git
cd gerion-cli
pip install .
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
- `markdown`: Markdown format - Human-readable report with formatting
- `sarif`: SARIF format - Standard format for static analysis results

### Secrets Scan

To perform a secrets scan on your codebase, run the following command:

```sh
gerion-cli secrets-scan [OPTIONS] [CODE_PATH]
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
gerion-cli secrets-scan /path/to/code

# Using command-line parameters with debug logging
gerion-cli secrets-scan --api-url https://api.gerion.com --client-id your-client-id --client-secret your-client-secret --log-level debug /path/to/code

# Save results to JSON file (default format)
gerion-cli secrets-scan --output-file scan_results.json /path/to/code

# Save results to Markdown file
gerion-cli secrets-scan --output-file scan_report.md --format markdown /path/to/code

# Save results to SARIF file
gerion-cli secrets-scan --output-file scan_results.sarif --format sarif /path/to/code

# Display results in console only (no credentials provided)
gerion-cli secrets-scan /path/to/code
```

### Software Component Analysis (SCA)

To perform software component analysis on your codebase, run the following command:

```sh
gerion-cli sca-scan [OPTIONS] [CODE_PATH]
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
gerion-cli sca-scan /path/to/code

# Using command-line parameters with debug logging
gerion-cli sca-scan --api-url https://api.gerion.com --client-id your-client-id --client-secret your-client-secret --log-level debug /path/to/code

# Save results to JSON file (default format)
gerion-cli sca-scan --output-file scan_results.json /path/to/code

# Save results to Markdown file
gerion-cli sca-scan --output-file scan_report.md --format markdown /path/to/code

# Save results to SARIF file
gerion-cli sca-scan --output-file scan_results.sarif --format sarif /path/to/code

# Display results in console only (no credentials provided)
gerion-cli sca-scan /path/to/code
```

## Output Format Examples

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

### 🔴 Finding 1: Hard coded secret: AWS_ACCESS_KEY_ID

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
    python -m gerion_cli.main secrets-scan /path/to/code
    python -m gerion_cli.main sca-scan /path/to/code
    ```

## Docker Usage

You can also use the provided Docker image which includes all necessary tools:

```sh
# Using environment variables
docker run --rm -e GERION_API_URL="https://api.gerion.com" -e GERION_CLIENT_ID="your-client-id" -e GERION_CLIENT_SECRET="your-client-secret" -v "$PWD:/code" gerion-cli secrets-scan /code

# Using command-line parameters
docker run --rm -v "$PWD:/code" gerion-cli secrets-scan --api-url https://api.gerion.com --client-id your-client-id --client-secret your-client-secret /code

# Save results to different formats
docker run --rm -v "$PWD:/code" gerion-cli secrets-scan --output-file results.md --format markdown /code
```

## License

This project is licensed under the Apache2.0 License. See the [LICENSE](LICENSE) file for more details.

## Acknowledgments

We would like to thank all contributors and users who have helped make this tool better.

---

Feel free to reach out if you have any questions or need further assistance!