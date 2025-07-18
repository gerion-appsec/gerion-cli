"""
Console table functionality for Gerion CLI.
"""
from typing import List, Dict
from rich.table import Table
from gerion_cli.core.logging import console, success

def findings_table(findings: List[Dict], scan_type: str = "Security"):
    """
    Display findings in a formatted table, sorted by severity.
    
    Args:
        findings: List of finding dictionaries
        scan_type: Type of scan (e.g., "Secrets", "SCA")
    """
    if not findings:
        success("No security findings detected")
        return
    
    # Sort findings by severity (Critical > High > Medium > Low > Info)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    
    def sort_key(finding):
        severity = finding.get('severity', 'Info')
        # Normalize severity to handle case variations
        severity_normalized = severity.capitalize()
        return severity_order.get(severity_normalized, 5)
    
    sorted_findings = sorted(findings, key=sort_key)
    
    # Create table
    table = Table(title=f"{scan_type} Findings", show_header=True, header_style="bold magenta")
    
    # Add columns based on scan type
    if scan_type == "Secrets":
        table.add_column("Severity", style="bold")
        table.add_column("Title", style="bold")
        table.add_column("File:Line", style="cyan")
        
        for finding in sorted_findings:
            severity = finding.get('severity', 'Info')
            # Normalize severity for consistent display
            severity_normalized = severity.capitalize()
            severity_color = {
                'Critical': 'bright_black',
                'High': 'red',
                'Medium': 'yellow',
                'Low': 'green',
                'Info': 'blue'
            }.get(severity_normalized, 'white')
            
            table.add_row(
                f"[{severity_color}]{severity_normalized}[/{severity_color}]",
                finding.get('title', 'N/A'),
                f"{finding.get('file_path', 'N/A')}:{finding.get('line_number', 'N/A')}"
            )
    elif scan_type == "IaC":
        table.add_column("Severity", style="bold")
        table.add_column("ID/Title", style="bold")
        table.add_column("File:Line", style="cyan")
        table.add_column("Status", style="magenta")
        for finding in sorted_findings:
            severity = finding.get('severity', 'Info')
            severity_normalized = severity.capitalize()
            severity_color = {
                'Critical': 'bright_black',
                'High': 'red',
                'Medium': 'yellow',
                'Low': 'green',
                'Info': 'blue'
            }.get(severity_normalized, 'white')
            table.add_row(
                f"[{severity_color}]{severity_normalized}[/{severity_color}]",
                finding.get('title', 'N/A'),
                f"{finding.get('file_path', 'N/A')}:{finding.get('line_number', 'N/A')}",
                finding.get('mitigation', 'N/A')[:40]  # Show first 40 chars of mitigation/status
            )
    else:  # SCA
        table.add_column("Severity", style="bold")
        table.add_column("CVE", style="bold")
        table.add_column("Component", style="cyan")
        table.add_column("File", style="cyan")
        
        for finding in sorted_findings:
            severity = finding.get('severity', 'Info')
            # Normalize severity for consistent display
            severity_normalized = severity.capitalize()
            severity_color = {
                'Critical': 'bright_black',
                'High': 'red',
                'Medium': 'yellow',
                'Low': 'green',
                'Info': 'blue'
            }.get(severity_normalized, 'white')
            
            component = f"{finding.get('component_name', 'N/A')} {finding.get('component_version', '')}"
            
            table.add_row(
                f"[{severity_color}]{severity_normalized}[/{severity_color}]",
                finding.get('cve', 'N/A'),
                component,
                finding.get('file_path', 'N/A')
            )
    
    console.print(table) 