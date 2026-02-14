import subprocess
import json
import os
import shutil
import tempfile
from typing import List, Dict, Any, Optional
from gerion_cli.core.logging import error, warning

# Premium Feature Hooks
try:
    from gerion_cli.pro import StructuralEngine
    HAS_PRO = True
except ImportError:
    HAS_PRO = False

def run_sast_tool(code_path: str, timeout: int = 180) -> List[Dict[str, Any]]:
    """
    Run SAST scan using Opengrep.
    If Premium (HAS_PRO): Runs Structural Search (Context + Reachability) to enrich findings.
    
    Returns:
        list: enriched_opengrep_results
    """
    results = []

    if not shutil.which("opengrep"):
        error("Opengrep tool not found in PATH.")
        return []

    # Create a temporary file for the report
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_report:
        report_path = temp_report.name

    # Calculate tool timeout (allow 10s buffer for CLI overhead)
    tool_timeout = max(1, timeout - 10)

    # 1. Run Opengrep (OSS)
    command = [
        "opengrep", "scan",
        "--config", "auto",
        "--timeout", str(tool_timeout),
        "--json",
        "--output", report_path,
        "--disable-version-check", # Optimization: skip version check for speed
        code_path
    ]
    
    try:
        # Opengrep returns non-zero on findings, so check=False
        subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
        
        if os.path.exists(report_path):
            with open(report_path, 'r') as file:
                data = json.load(file)
            if data:
                results = data.get('results', [])
    except subprocess.TimeoutExpired:
        error(f"SAST scan timed out after {timeout} seconds.")
        return []
    except Exception as e:
        error(f"An error occurred while running SAST scan: {e}")
    finally:
        if os.path.exists(report_path):
            try: os.remove(report_path)
            except: pass

    # 2. Run Premium Structural Engine (If Available)
    if HAS_PRO and results:
        try:
            engine = StructuralEngine()
            engine.analyze_reachability(results, code_path)
        except Exception as e:
            warning(f"Structural Engine failed: {e}")
            
    return results
