"""
SCA (Software Component Analysis) tool integration.
"""
import subprocess
import json
import os
import shutil
import tempfile
from gerion_cli.core.logging import error, warning

def run_sca_tool(code_path, timeout=180):
    if not shutil.which("osv-scanner"):
        error("OSV-Scanner tool not found in PATH.")
        return []

    # Create a temporary file for the report
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_report:
        report_path = temp_report.name

    # Calculate tool timeout (allow 10s buffer for CLI overhead)
    tool_timeout = max(1, timeout - 10)
    
    # OSV-Scanner command
    # Usage: osv-scanner scan --format json --output <file> <path>
    command = [
        "osv-scanner", "scan",
        "--no-resolve",
        "--format", "json",
        "--output", report_path,
        "-r", # Recursive scan
        code_path
    ]
    
    try:
        # OSV-Scanner returns non-zero on vulnerabilities, so check=False
        subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
        
        # Check if report file exists
        if not os.path.exists(report_path):
            return []
        
        # Read and parse JSON
        with open(report_path, 'r') as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                # OSV-Scanner might create an empty file if no vulns
                return []
                
            if not data:
                return []
                
            # OSV-Scanner returns a root dict with "results"
            results = data.get('results', [])
            return results if results is not None else []

    except subprocess.TimeoutExpired:
        error(f"SCA scan timed out after {timeout} seconds.")
        return []

    except Exception as e:
        error(f"An error occurred while running SCA scan: {e}")
        return []
    finally:
        if os.path.exists(report_path):
            try: os.remove(report_path)
            except OSError: pass