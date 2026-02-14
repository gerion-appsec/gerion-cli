"""
Console table functionality for Gerion CLI.
"""
from typing import List, Dict
from rich.table import Table
from rich.console import Console
from gerion_cli.core.logging import success

console = Console()

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
        # Check if any finding has confidence
        has_premium = any(f.get('confidence') for f in findings)
        
        table.add_column("Severity", style="bold")
        if has_premium:
            table.add_column("Confidence", style="bold yellow")
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
            
            row = [
                f"[{severity_color}]{severity_normalized}[/{severity_color}]"
            ]
            if has_premium:
                row.append(str(finding.get('confidence') or 'N/A'))
            
            row.extend([
                finding.get('title', 'N/A'),
                f"{finding.get('file_path', 'N/A')}:{finding.get('line_number', 'N/A')}"
            ])
            table.add_row(*row)
    elif scan_type == "SAST":
        # Check if any finding has reachability
        has_premium = any(f.get('reachability') for f in sorted_findings)
        
        table.add_column("Severity", style="bold")
        if has_premium:
            table.add_column("Risk", style="bold magenta")
            table.add_column("Reachab.", style="bold yellow")
            table.add_column("Conf.", style="bold cyan")
            
        table.add_column("Rule", style="bold")
        table.add_column("File:Line", style="cyan")
        
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
            
            row = [
                f"[{severity_color}]{severity_normalized}[/{severity_color}]"
            ]
            if has_premium:
                row.append(str(finding.get('risk_score', 'N/A')))
                row.append(str(finding.get('reachability', 'N/A')))
                row.append(str(finding.get('confidence', 'N/A')))
                
            row.extend([
                finding.get('title', 'N/A'), # Rule ID is title
                f"{finding.get('file_path', 'N/A')}:{finding.get('line_number', 'N/A')}"
            ])
            table.add_row(*row)
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
        # Check if any finding has reachability
        has_premium = any(f.get('reachability') for f in findings)
        
        table.add_column("Severity", style="bold")
        if has_premium:
            table.add_column("Risk Score", style="bold magenta")
            table.add_column("Reachability", style="bold yellow")
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
            
            row = [
                f"[{severity_color}]{severity_normalized}[/{severity_color}]"
            ]
            if has_premium:
                risk_score = str(finding.get('risk_score') or 'N/A')
                reachability = str(finding.get('reachability') or 'N/A')
                row.extend([risk_score, reachability])
            
            row.extend([
                finding.get('cve', 'N/A'),
                component,
                finding.get('file_path', 'N/A')
            ])
            
            table.add_row(*row)
    
    console.print(table) 