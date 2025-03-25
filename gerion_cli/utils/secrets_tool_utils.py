import subprocess
import json
import os

report_path = "gerion-cli-secrets-report.json"

def run_secrets_tool(code_path):
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
