"""
IaC (Infrastructure as Code) scan tool integration.
"""
import subprocess
import json
import os
import shutil
import tempfile
from gerion_cli.core.logging import error, warning

def run_iac_tool(code_path, timeout=180, queries_path=None):
    kics_path = shutil.which("kics")
    if not kics_path:
        error("KICS tool not found in PATH.")
        return []

    # Create a temporary file for the report
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_report:
        report_path = temp_report.name

    # Calculate tool timeout (allow 10s buffer for CLI overhead)
    tool_timeout = max(1, timeout - 10)

    # KICS command
    # Usage: kics scan --path <path> --output-path <dir> --output-name <filename> --report-formats json
    # Note: KICS output handling is a bit specific. It writes to a directory/file combo.
    # We'll use the temp file name, but KICS needs just the name and path separated.
    report_dir = os.path.dirname(report_path)
    report_name = os.path.basename(report_path).replace('.json', '') # KICS adds extension
    
    command = [
        "kics", "scan",
        "--path", code_path,
        "--output-path", report_dir,
        "--output-name", report_name,
        "--report-formats", "json",
        "--timeout", str(tool_timeout),
        "--ignore-on-exit", "results", # Exit 0 even if findings found
        "--no-color",
        "--ci"
    ]
    
    # Priority:
    # 1. Explicitly passed queries_path
    # 2. auto-detection relative to binary
    
    if queries_path:
        command.extend(["--queries-path", queries_path])
    else:
        # Auto-detect queries path if not provided
        kics_bin_dir = os.path.dirname(os.path.realpath(kics_path))
        potential_queries_path = os.path.join(kics_bin_dir, 'assets', 'queries')
        if os.path.exists(potential_queries_path):
            command.extend(["--queries-path", potential_queries_path])

    try:
        subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
        
        # KICS likely created <report_path> (since we stripped extension and KICS adds it back for json)
        # Verify the file exists
        if not os.path.exists(report_path):
             return []
        
        # Read and parse JSON
        with open(report_path, 'r') as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                return []
                
            if not data:
                return []
                
            # KICS returns a dict with "queries" (list of findings grouped by query)
            # We want to return raw data for parser to handle, or flatten here?
            # Parser expects a list of findings usually. KICS structure is deep.
            # Let's return the root data object so parser can traverse "queries"
            # But run_iac_tool signature implies a list return? 
            # Previous trivial impl returned list of results. 
            # Let's return the 'queries' list directly.
            return data.get('queries', [])
            
    except subprocess.TimeoutExpired:
        error(f"IaC scan timed out after {timeout} seconds.")
        return []
    except Exception as e:
        error(f"An error occurred while running IaC scan: {e}")
        return []
    finally:
        if os.path.exists(report_path):
            try: os.remove(report_path)
            except: pass 