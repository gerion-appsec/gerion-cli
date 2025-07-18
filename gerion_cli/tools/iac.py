"""
IaC (Infrastructure as Code) scan tool integration.
"""
import subprocess
import json
import os

report_path = "gerion-cli-iac-report.json"

def run_iac_tool(code_path):
    command = [
        "trivy", "config", "-f", "json", "-o", report_path, code_path
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        with open(report_path, 'r') as file:
            data = json.load(file)
            return data.get('Results', data)  # fallback to data if 'Results' not present
    except Exception as e:
        print(f"An error occurred while reading the JSON file: {e}")
        return None
    finally:
        if os.path.exists(report_path):
            os.remove(report_path) 