"""
SCA (Software Component Analysis) tool integration.
"""
import subprocess
import json
import os

report_path = "gerion-cli-sca-report.json"

def run_sca_tool(code_path):
    command = ["trivy", "fs", "--scanners", "vuln", "-f", "json", "--exit-code", "0",  "-o", report_path, code_path]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        with open(report_path, 'r') as file:
            data = json.load(file)
            return data['Results']
    except Exception as e:
        print(f"An error occurred while reading the JSON file: {e}")
        return None
    finally:
        if os.path.exists(report_path):
            os.remove(report_path) 