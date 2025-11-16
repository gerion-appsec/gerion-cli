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
        
        # Check if report file exists
        if not os.path.exists(report_path):
            return []
        
        # Read and parse JSON
        with open(report_path, 'r') as file:
            data = json.load(file)
            # Handle empty results or missing Results key
            if not data:
                return []
            # Return Results if present, otherwise return empty list
            results = data.get('Results', [])
            # Ensure we return a list (Results might be None)
            return results if results is not None else []
    except json.JSONDecodeError as e:
        print(f"An error occurred while parsing the JSON file: {e}")
        return []
    except KeyError as e:
        print(f"An error occurred while reading the JSON file: Missing key {e}")
        return []
    except Exception as e:
        print(f"An error occurred while reading the JSON file: {e}")
        return []
    finally:
        if os.path.exists(report_path):
            os.remove(report_path) 