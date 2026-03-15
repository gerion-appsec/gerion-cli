"""
Secrets detection tool integration.
"""
import subprocess
import json
import os
import shutil
import tempfile
from gerion_cli.core.logging import error, warning

def run_secrets_tool(code_path, timeout=180):
    if not shutil.which("gitleaks"):
        error("Gitleaks tool not found in PATH.")
        return []

    # Create a temporary file for the report
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_report:
        report_path = temp_report.name

    command = ["gitleaks", "dir", code_path, "--exit-code", "0", "-f", "json", "-r", report_path]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        with open(report_path, 'r') as file:
            data = json.load(file)
            return data
    except subprocess.TimeoutExpired:
        error(f"Secrets scan timed out after {timeout} seconds.")
        return []
    except Exception as e:
        error(f"An error occurred while reading the JSON file: {e}")
        return None
    finally:
        if os.path.exists(report_path):
            os.remove(report_path) 