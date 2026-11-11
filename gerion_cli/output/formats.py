"""
Output format functionality for Gerion CLI.
"""
import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from gerion_cli.core.config import __version__
from gerion_cli.core.logging import info, warning
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

_EXTENSION_FORMATS = {
    '.json': OutputFormat.JSON,
    '.md': OutputFormat.MARKDOWN,
    '.markdown': OutputFormat.MARKDOWN,
    '.sarif': OutputFormat.SARIF,
}


def resolve_file_format(filename: str, output_format: OutputFormat | None) -> OutputFormat:
    """Format for --output-file: the explicit --format, else inferred from the extension."""
    if output_format and output_format != OutputFormat.TABLE:
        return output_format
    if output_format == OutputFormat.TABLE:
        warning("The table format cannot be written to a file; using the file extension instead.")
    for extension, inferred in _EXTENSION_FORMATS.items():
        if filename.lower().endswith(extension):
            return inferred
    warning(f"Could not infer format from file '{filename}'. Defaulting to JSON.")
    return OutputFormat.JSON


def save_to_file(results: dict[str, Any], filename: str, output_format: OutputFormat = OutputFormat.JSON):
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

def generate_json_content(results: dict[str, Any]) -> str:
    """Generate JSON content from results."""
    return json.dumps(results, indent=4)

def save_as_json(results: dict[str, Any], filename: str):
    """Save results as JSON format."""
    content = generate_json_content(results)
    with open(filename, 'w') as json_file:
        json_file.write(content)
    info(f"Results saved to {filename} (JSON format)")

def _md_cve(value: Any) -> str:
    """CVE field for display: SCA findings carry a list of ids."""
    if isinstance(value, (list, tuple)):
        return ', '.join(str(item) for item in value) or 'N/A'
    return str(value) if value else 'N/A'


def _md_cell(value: Any) -> str:
    """Make a value safe for a Markdown table cell: no row breaks or column splits."""
    return re.sub(r'\s*[\r\n]+\s*', ' ', str(value)).replace('|', '\\|')


def save_as_markdown(results: dict[str, Any], filename: str):
    """Save results as Markdown format."""
    markdown_content = generate_markdown_content(results)
    with open(filename, 'w', encoding='utf-8') as md_file:
        md_file.write(markdown_content)

    info(f"Results saved to {filename} (Markdown format)")

def generate_markdown_content(results: dict[str, Any]) -> str:
    """Generate Markdown content from results."""
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

                component = _md_cell(f"{finding.get('component_name', 'N/A')} {finding.get('component_version', '')}")
                cve = _md_cell(_md_cve(finding.get('cve')))
                file_path = _md_cell(finding.get('file_path', 'N/A'))

                if has_premium:
                    risk_score = _md_cell(finding.get('risk_score', 'N/A'))
                    reachability = _md_cell(finding.get('reachability', 'N/A'))
                    markdown_content += f"| {severity_emoji} {severity_normalized} | {risk_score} | {reachability} | {cve} | {component} | `{file_path}` |\n"
                else:
                    markdown_content += f"| {severity_emoji} {severity_normalized} | {cve} | {component} | `{file_path}` |\n"

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

                title = _md_cell(finding.get('title', 'N/A'))
                file_line = _md_cell(f"{finding.get('file_path', 'N/A')}:{finding.get('line_number', 'N/A')}")

                if has_premium:
                    confidence = _md_cell(finding.get('confidence', 'N/A'))
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
                markdown_content += f"- **CVE**: {_md_cve(finding.get('cve'))}\n"
                markdown_content += f"- **Component**: {finding.get('component_name', 'N/A')} {finding.get('component_version', '')}\n"

            markdown_content += f"- **Description**: {sanitize_verbose_text(finding.get('description', 'N/A'))}\n"

            if finding.get('mitigation'):
                markdown_content += f"- **Mitigation**: {sanitize_verbose_text(finding.get('mitigation', 'N/A'))}\n"

            markdown_content += "\n---\n\n"

    return markdown_content

def save_as_sarif(results: dict[str, Any], filename: str):
    """Save results as SARIF format."""
    sarif_data = generate_sarif_content(results)
    with open(filename, 'w') as sarif_file:
        json.dump(sarif_data, sarif_file, indent=2)

    info(f"Results saved to {filename} (SARIF format)")

_SARIF_LEVELS = {
    'CRITICAL': 'error',
    'HIGH': 'error',
    'MEDIUM': 'warning',
    'LOW': 'note',
    'INFO': 'note',
}


def _sarif_start_line(line_number: Any) -> int:
    """SARIF requires an integer >= 1; scanners may give None, 0 or a string."""
    try:
        return max(1, int(line_number))
    except (TypeError, ValueError):
        return 1


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def generate_sarif_content(results: dict[str, Any]) -> dict[str, Any]:
    """Generate SARIF 2.1.0 content from results."""
    metadata = results.get('metadata', {})
    findings = results.get('findings', [])

    # Scan type from metadata ('All' for scan-all), else from the findings
    scan_type = metadata.get('scan_type') or "Security"
    if not metadata.get('scan_type') and findings:
        scan_type = findings[0].get('scan_type') or 'Security'

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": f"Gerion {scan_type} Scanner",
                        "version": __version__,
                        "informationUri": "https://gerion-appsec.com"
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')
                    }
                ],
                "results": []
            }
        ]
    }

    # Convert findings to SARIF format
    for finding in findings:
        severity = str(finding.get('severity') or 'INFO').upper()
        finding_id = finding.get('finding_id') or 'unknown'

        sarif_result = {
            "ruleId": finding_id,
            "level": _SARIF_LEVELS.get(severity, 'note'),
            "message": {
                "text": finding.get('description') or finding.get('title') or 'No description available'
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": quote(str(finding.get('file_path') or 'unknown'), safe='/')
                        },
                        "region": {
                            "startLine": _sarif_start_line(finding.get('line_number')),
                            "startColumn": 1
                        }
                    }
                }
            ],
            # Stable identity across runs so code scanning tracks the same alert
            "partialFingerprints": {
                "gerionFindingId/v1": finding_id
            }
        }

        # Add additional properties
        properties = {}
        if finding.get('cve'):
            properties['cve'] = _as_list(finding.get('cve'))
        if finding.get('component_name'):
            properties['component'] = f"{finding.get('component_name')} {finding.get('component_version') or ''}".strip()
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

    return sarif_data

def print_formatted(results: dict[str, Any], output_format: OutputFormat):
    """
    Print results to stdout in the specified format.
    """
    if output_format == OutputFormat.JSON:
        print(generate_json_content(results))
    elif output_format == OutputFormat.MARKDOWN:
        print(generate_markdown_content(results))
    elif output_format == OutputFormat.SARIF:
        print(json.dumps(generate_sarif_content(results), indent=2))
    else:
        raise ValueError(f"Unsupported output format: {output_format}")
