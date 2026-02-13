"""
Secrets detection tool integration.
"""
import subprocess
import json
import os

import shutil

import tempfile

def run_secrets_tool(code_path):
    if not shutil.which("gitleaks"):
        print("Gitleaks tool not found in PATH.")
        return []

    # Create a temporary file for the report
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_report:
        report_path = temp_report.name

    command = ["gitleaks", "dir", code_path, "--exit-code", "0", "-f", "json", "-r", report_path]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        with open(report_path, 'r') as file:
            data = json.load(file)
            return data
    except Exception as e:
        print(f"An error occurred while reading the JSON file: {e}")
        return None
    finally:
        if os.path.exists(report_path):
            os.remove(report_path) 