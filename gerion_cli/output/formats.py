"""
Output format functionality for Gerion CLI.
"""
import json
import re
from datetime import datetime
from typing import Dict, List, Any
from gerion_cli.core.logging import info
from gerion_cli.core.types import OutputFormat

def sanitize_verbose_text(text: str) -> str:
    """
    Sanitize verbose text fields (description, mitigation) for safe insertion into Markdown.
    Only removes problematic characters that could break Markdown rendering.
    """
    if not text:
        return "N/A"
    
    # Convert to string and remove problematic characters
    text = str(text)
    # Remove control characters that could break Markdown
    text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
    
    return text

def save_to_file(results: Dict[str, Any], filename: str, output_format: OutputFormat = OutputFormat.JSON):
    """
    Save results to a file in the specified format.
    
    Args:
        results: The scan results dictionary
        filename: Output filename
        output_format: Format to save the file in
    """
    if output_format == OutputFormat.JSON:
        save_as_json(results, filename)
    elif output_format == OutputFormat.MARKDOWN:
        save_as_markdown(results, filename)
    elif output_format == OutputFormat.SARIF:
        save_as_sarif(results, filename)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")

def save_as_json(results: Dict[str, Any], filename: str):
    """Save results as JSON format."""
    with open(filename, 'w') as json_file:
        json.dump(results, json_file, indent=4)
    info(f"Results saved to {filename} (JSON format)")

def save_as_markdown(results: Dict[str, Any], filename: str):
    """Save results as Markdown format."""
    metadata = results.get('metadata', {})
    findings = results.get('findings', [])
    
    # Determine scan type from findings
    scan_type = "Security"
    if findings:
        scan_type = findings[0].get('scan_type', 'Security')
    
    markdown_content = f"""# {scan_type} Scan Report

## Scan Summary

- **Repository**: {metadata.get('repository_name', 'N/A')}
- **Branch**: {metadata.get('branch_name', 'N/A')}
- **Commit**: {metadata.get('commit_hash', 'N/A')}
- **Scan Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Total Findings**: {len(findings)}

## Findings

"""
    
    if not findings:
        markdown_content += "✅ **No security findings detected**\n"
    else:
        # Sort findings by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        
        def sort_key(finding):
            severity = finding.get('severity', 'Info')
            # Normalize severity to handle case variations
            severity_normalized = severity.capitalize()
            return severity_order.get(severity_normalized, 5)
        
        sorted_findings = sorted(findings, key=sort_key)
        
        # Create table header based on scan type
        if scan_type == "SCA":
            # Check if any finding has reachability data
            has_premium = any(f.get('reachability') for f in findings)
            
            if has_premium:
                markdown_content += "| Severity | Risk Score | Reachability | CVE | Component | File |\n"
                markdown_content += "|----------|------------|--------------|-----|-----------|------|\n"
            else:
                markdown_content += "| Severity | CVE | Component | File |\n"
                markdown_content += "|----------|-----|-----------|------|\n"
            
            for finding in sorted_findings:
                severity = finding.get('severity', 'Info')
                severity_normalized = severity.capitalize()
                severity_emoji = {
                    'Critical': '🚨',
                    'High': '🔴', 
                    'Medium': '🟡',
                    'Low': '🟢',
                    'Info': '🔵'
                }.get(severity_normalized, '⚪')
                
                component = f"{finding.get('component_name', 'N/A')} {finding.get('component_version', '')}"
                
                if has_premium:
                    risk_score = finding.get('risk_score', 'N/A')
                    reachability = finding.get('reachability', 'N/A')
                    markdown_content += f"| {severity_emoji} {severity_normalized} | {risk_score} | {reachability} | {finding.get('cve', 'N/A')} | {component} | `{finding.get('file_path', 'N/A')}` |\n"
                else:
                    markdown_content += f"| {severity_emoji} {severity_normalized} | {finding.get('cve', 'N/A')} | {component} | `{finding.get('file_path', 'N/A')}` |\n"
        
        else:  # Secrets
            # Check if any finding has confidence data
            has_premium = any(f.get('confidence') for f in findings)
            
            if has_premium:
                markdown_content += "| Severity | Confidence | Title | File:Line |\n"
                markdown_content += "|----------|------------|-------|-----------|\n"
            else:
                markdown_content += "| Severity | Title | File:Line |\n"
                markdown_content += "|----------|-------|-----------|\n"
            
            for finding in sorted_findings:
                severity = finding.get('severity', 'Info')
                severity_normalized = severity.capitalize()
                severity_emoji = {
                    'Critical': '🚨',
                    'High': '🔴', 
                    'Medium': '🟡',
                    'Low': '🟢',
                    'Info': '🔵'
                }.get(severity_normalized, '⚪')
                
                title = finding.get('title', 'N/A')
                file_line = f"{finding.get('file_path', 'N/A')}:{finding.get('line_number', 'N/A')}"
                
                if has_premium:
                    confidence = finding.get('confidence', 'N/A')
                    markdown_content += f"| {severity_emoji} {severity_normalized} | {confidence} | {title} | `{file_line}` |\n"
                else:
                    markdown_content += f"| {severity_emoji} {severity_normalized} | {title} | `{file_line}` |\n"
        
        # Add detailed findings section
        markdown_content += "\n## Detailed Findings\n\n"
        
        for finding in sorted_findings:
            severity = finding.get('severity', 'Info')
            severity_normalized = severity.capitalize()
            severity_emoji = {
                'Critical': '🚨',
                'High': '🔴', 
                'Medium': '🟡',
                'Low': '🟢',
                'Info': '🔵'
            }.get(severity_normalized, '⚪')
            
            markdown_content += f"### {severity_emoji} {finding.get('title', 'N/A')}\n\n"
            markdown_content += f"- **Severity**: {severity_normalized}\n"
            
            if finding.get('confidence'):
                markdown_content += f"- **Confidence**: {finding.get('confidence')}\n"
            if finding.get('risk_score'):
                markdown_content += f"- **Risk Score**: {finding.get('risk_score')}\n"
            if finding.get('reachability'):
                markdown_content += f"- **Reachability**: {finding.get('reachability')}\n"
            
            if finding.get('score_breakdown'):
                sb = finding['score_breakdown']
                markdown_content += "- **Scoring Details**:\n"
                markdown_content += f"  - Base Section: {sb.get('score_base', 0)}\n" 
                markdown_content += f"  - Verificability: {sb.get('score_verificability', 1.0)}\n"
                markdown_content += f"  - Reachability: {sb.get('score_reachability', 0.9)}\n"
                markdown_content += f"  - Environment: {sb.get('score_environment', 1.0)}\n"

            markdown_content += f"- **File**: `{finding.get('file_path', 'N/A')}`"
            
            if finding.get('line_number'):
                markdown_content += f":{finding.get('line_number')}"
            markdown_content += "\n"
            
            if scan_type == "SCA":
                markdown_content += f"- **CVE**: {finding.get('cve', 'N/A')}\n"
                markdown_content += f"- **Component**: {finding.get('component_name', 'N/A')} {finding.get('component_version', '')}\n"
            
            markdown_content += f"- **Description**: {sanitize_verbose_text(finding.get('description', 'N/A'))}\n"
            
            if finding.get('mitigation'):
                markdown_content += f"- **Mitigation**: {sanitize_verbose_text(finding.get('mitigation', 'N/A'))}\n"
            
            markdown_content += "\n---\n\n"
    
    with open(filename, 'w', encoding='utf-8') as md_file:
        md_file.write(markdown_content)
    
    info(f"Results saved to {filename} (Markdown format)")

def save_as_sarif(results: Dict[str, Any], filename: str):
    """Save results as SARIF format."""
    metadata = results.get('metadata', {})
    findings = results.get('findings', [])
    
    # Determine scan type from findings
    scan_type = "Security"
    if findings:
        scan_type = findings[0].get('scan_type', 'Security')
    
    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": f"Gerion {scan_type} Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://gerion-appsec.com"
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": datetime.now().isoformat() + "Z"
                    }
                ],
                "results": []
            }
        ]
    }
    
    # Convert findings to SARIF format
    for finding in findings:
        severity = finding.get('severity', 'Info')
        sarif_level = {
            'Critical': 'error',
            'High': 'error',
            'Medium': 'warning', 
            'Low': 'note',
            'Info': 'note'
        }.get(severity, 'note')
        
        sarif_result = {
            "ruleId": finding.get('finding_id', 'unknown'),
            "level": sarif_level,
            "message": {
                "text": finding.get('description', 'No description available')
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get('file_path', 'unknown')
                        },
                        "region": {
                            "startLine": finding.get('line_number', 1),
                            "startColumn": 1
                        }
                    }
                }
            ]
        }
        
        # Add additional properties
        properties = {}
        if finding.get('cve'):
            properties['cve'] = finding.get('cve')
        if finding.get('component_name'):
            properties['component'] = f"{finding.get('component_name')} {finding.get('component_version', '')}"
        if finding.get('mitigation'):
            properties['mitigation'] = finding.get('mitigation')
        
        # Add Premium Fields to SARIF properties
        if finding.get('confidence'):
            properties['confidence'] = finding.get('confidence')
        if finding.get('reachability'):
            properties['reachability'] = finding.get('reachability')
        if finding.get('risk_score') is not None:
            properties['riskScore'] = finding.get('risk_score')
        if finding.get('score_breakdown'):
            properties['gerionScoreBreakdown'] = finding.get('score_breakdown')
        
        if properties:
            sarif_result['properties'] = properties
        
        sarif_data['runs'][0]['results'].append(sarif_result)
    
    with open(filename, 'w') as sarif_file:
        json.dump(sarif_data, sarif_file, indent=2)
    
    info(f"Results saved to {filename} (SARIF format)") 