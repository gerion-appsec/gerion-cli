import subprocess
import json
import os
import shutil
from typing import List, Dict, Any, Optional

# Premium Feature Hooks
try:
    from gerion_cli.pro import StructuralEngine
    HAS_PRO = True
except ImportError:
    HAS_PRO = False

report_path = "semgrep_report.json"

def run_sast_tool(code_path: str) -> List[Dict[str, Any]]:
    """
    Run SAST scan using Semgrep.
    If Premium (HAS_PRO): Runs Structural Search (Context + Reachability) to enrich findings.
    
    Returns:
        list: enriched_semgrep_results
    """
    results = []

    # 1. Run Semgrep (OSS)
    command = [
        "semgrep", "scan",
        "--config", "auto",
        "--json",
        "--output", report_path,
        code_path
    ]
    
    if not shutil.which("semgrep"):
        print("Semgrep tool not found in PATH.")
        return []

    try:
        # Semgrep returns non-zero on findings, so check=False
        subprocess.run(command, capture_output=True, text=True, check=False)
        
        if os.path.exists(report_path):
            with open(report_path, 'r') as file:
                data = json.load(file)
            if data:
                results = data.get('results', [])
    except Exception as e:
        print(f"An error occurred while running SAST scan: {e}")
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
            print(f"Structural Engine failed: {e}")
            
    return results
