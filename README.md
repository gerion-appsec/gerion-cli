# Gerion CLI

A powerful command-line interface for performing security scans on your codebase. The Gerion CLI allows you to scan for secrets and perform software component analysis (SCA) with ease.

## Features

- **Secrets Scan**: Detect sensitive information such as API keys, passwords, and other secrets in your code.
- **Software Component Analysis (SCA)**: Identify vulnerabilities in your project's dependencies.
- **API Integration**: Send scan results to a specified API for further processing or storage.
- **JSON Output**: Save scan results to a JSON file for easy integration with other tools.

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

## Usage

### Secrets Scan

To perform a secrets scan on your codebase, run the following command:

```sh
gerion-cli secrets-scan [OPTIONS] [CODE_PATH]
```

**Options:**

- `--api-url TEXT`: API URL for sending results.
- `--api-token TEXT`: API token for authentication.
- `--output-file TEXT`: Save results to a JSON file.

**Example:**

```sh
gerion-cli secrets-scan --api-url https://example.com/api --api-token abc123 --output-file scan_results.json /path/to/code
```

### Software Component Analysis (SCA)

To perform software component analysis on your codebase, run the following command:

```sh
gerion-cli sca-scan [OPTIONS] [CODE_PATH]
```

**Options:**

- `--api-url TEXT`: API URL for sending results.
- `--api-token TEXT`: API token for authentication.
- `--output-file TEXT`: Save results to a JSON file.

**Example:**

```sh
gerion-cli sca-scan --api-url https://example.com/api --api-token abc123 --output-file scan_results.json /path/to/code
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

- Python 3.7 or higher
- Typer
- HTTPX

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

3. Run the CLI locally:

    ```sh
    python main.py secrets-scan --api-url https://example.com/api --api-token abc123 /path/to/code
    python main.py sca-scan --api-url https://example.com/api --api-token abc123 /path/to/code
    ```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Acknowledgments

We would like to thank all contributors and users who have helped make this tool better.

---

Feel free to reach out if you have any questions or need further assistance!