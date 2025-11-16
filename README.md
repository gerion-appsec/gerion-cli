# 🚀 Gerion CLI

> **A blazing-fast, all-in-one security scanner for your codebase.**  
> Find secrets, vulnerable dependencies, and more — right from your terminal!

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](Dockerfile)

---

## ⚡️ Quick Start

```sh
git clone https://github.com/your-repo/gerion-cli.git
cd gerion-cli
poetry install
```

---

## 🛠️ Installation

- **With Poetry (recommended):**
  ```sh
  git clone https://github.com/your-repo/gerion-cli.git
  cd gerion-cli
  poetry install
  ```

- **With Docker:**
  ```sh
  docker build -t gerion-cli .
  ```

---

## 🚦 Usage

### Secrets Scan

```sh
poetry run python -m gerion_cli.main secrets-scan [OPTIONS] [CODE_PATH]
# Or with Docker:
docker run --rm -v "$PWD:/code" gerion-cli secrets-scan /code
```

### SCA Scan

```sh
poetry run python -m gerion_cli.main sca-scan [OPTIONS] [CODE_PATH]
# Or with Docker:
docker run --rm -v "$PWD:/code" gerion-cli sca-scan /code
```

### IaC Scan

```sh
poetry run python -m gerion_cli.main iac-scan [OPTIONS] [CODE_PATH]
# Or with Docker:
docker run --rm -v "$PWD:/code" gerion-cli iac-scan /code
```

### Common Options

- `--api-url TEXT`         API Gateway URL for sending results
- `--client-id TEXT`       Client ID for API authentication (default: gerion-cli-{version}, e.g., gerion-cli-0.1.0)
- `--api-key TEXT`         M2M API key for authentication
- `--output-file TEXT`     Save results to a file (disables API sending)
- `--format [json|markdown|sarif]`  Output format (default: json)
- `--log-level [debug|info|warning|error|critical]`  Set logging level

### Environment Variables

You can set credentials as environment variables (recommended for CI/CD):

```sh
export GERION_API_URL="https://api.gerion.com"
export GERION_API_KEY="your-m2m-api-key"
```

**Note**: 
- The `CLIENT_ID` is automatically set to `gerion-cli-{version}` (e.g., `gerion-cli-0.1.0`) based on the CLI version. This allows the API to identify which version of the CLI is making requests. You can override it with `GERION_CLIENT_ID` if needed, but it's not recommended.
- You need to create an M2M API key via the Gerion web interface or API before using the CLI. The API key is used for Machine-to-Machine authentication with the API Gateway.

---

## ✨ Features

- 🔑 **Secrets Scan**: Detect API keys, passwords, and other secrets in your code.
- 🛡️ **SCA (Dependency Analysis)**: Find vulnerabilities in your dependencies.
- 🏗️ **IaC Scan**: Detect misconfigurations in Infrastructure as Code (Terraform, Kubernetes, etc.).
- ☁️ **API Integration**: Optionally send results to a remote API.
- 🖨️ **Multiple Output Formats**: JSON, Markdown, SARIF.
- 🎨 **Beautiful Console Output**: Rich tables and colored logs.
- 🧠 **Automatic Git Metadata**: Each scan includes repo, branch, and commit info.
- 🔒 **Secure Credentials**: Secrets are never printed in logs.
- 🐳 **All-in-One Docker Image**: No need to install Trivy or Gitleaks manually.

---

## 🖥️ Example Output

```
┌──────────┬──────────────────────────────┬──────────────┐
│ Severity │ Title                        │ File:Line    │
├──────────┼──────────────────────────────┼──────────────┤
│ 🔴 High  │ Hard coded secret: AWS_KEY   │ config.py:42 │
└──────────┴──────────────────────────────┴──────────────┘
```

---

## 🤝 Contributing

1. Fork this repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push to your fork and submit a pull request.

---

## 📄 License

Apache 2.0. See [LICENSE](LICENSE).

---

## 🔗 Links

- [Documentation](#) <!-- Add real link if available -->
- [Issues](../../issues)
- [Gerion AppSec](https://gerion-appsec.com)
