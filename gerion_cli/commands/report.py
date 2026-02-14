import typer
import httpx
import os
from typing import Optional
from enum import Enum
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint
from datetime import datetime
from gerion_cli.core.metadata import get_metadata
from gerion_cli.core.config import CLIENT_ID
from gerion_cli.core.types import SecretString
from gerion_cli.api.auth import authenticate_with_api

console = Console()

class ReportFormat(str, Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    TEXT = "text"
    PDF = "pdf"

def report(
    path: str = typer.Argument(".", help="Path to the code directory", show_default=True),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Override repository name"),
    branch: Optional[str] = typer.Option(None, "--branch", "-b", help="Override branch name"),
    scan_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by scan type (SAST, SCA, IAC, SECRETS)"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by minimum severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    format: ReportFormat = typer.Option(ReportFormat.TEXT, "--format", "-f", help="Output format (text, json, markdown, pdf)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    api_url: Optional[str] = typer.Option(None, "--api-url", "-u", envvar="GERION_API_URL", help="API Gateway URL"),
    client_id: str = typer.Option(None, "--client-id", "-i", envvar="GERION_CLIENT_ID", help=f"Client ID for API authentication (default: {CLIENT_ID})"),
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="GERION_API_KEY", hide_input=True, help="M2M API key for authentication"),
    active_only: bool = typer.Option(True, "--active-only/--all", help="Only show active findings (default) or all including mitigated/FP"),
    include_description: bool = typer.Option(True, "--include-description/--no-description", help="Include finding descriptions (default: True)"),
    include_mitigation: bool = typer.Option(True, "--include-mitigation/--no-mitigation", help="Include remediation/mitigation advice (default: True)"),
):
    """
    Generate a security report for the current project or specified filters.
    """
    # 0. Set Effective Context
    effective_api_url = api_url or "http://localhost:8000"
    effective_client_id = client_id or CLIENT_ID
    api_key_string = SecretString.from_typer_option(api_key)

    # 1. Authentication
    # We use the M2M authentication flow to get a JWT token
    if not api_key_string:
        rprint("[red]Error: GERION_API_KEY environment variable is not set.[/red]")
        rprint("Please set your API key to authenticate.")
        raise typer.Abort()

    with console.status("[bold green]Authenticating..."):
        jwt_token = authenticate_with_api(effective_api_url, effective_client_id, api_key_string)
    
    if not jwt_token:
        # Error message is already printed by authenticate_with_api
        raise typer.Abort()
    # 1. Context Detection
    metadata = get_metadata(code_path=path)
    current_repo = repo or metadata.get("repository_name")
    current_branch = branch or metadata.get("branch_name")
    
    if not current_repo or current_repo == "local":
        rprint("[yellow]Warning: Could not detect a git repository. Using 'local' context.[/yellow]")
    
    rprint(f"[bold blue]Generating report for:[/bold blue] {current_repo} ({current_branch})")
    
    # 2. Fetch Findings
    filters = {
        "repository_name": current_repo if current_repo != "local" else None,
        "branch_name": current_branch if current_branch != "local" else None,
        "scan_type": scan_type,
        "severity": severity,
        "active_only": active_only,
        "limit": 1000
    }
    
    # Filter out None values
    params = {k: v for k, v in filters.items() if v is not None}
    
    try:
        with console.status("[bold green]Fetching findings..."):
            with httpx.Client() as client:
                response = client.get(
                    f"{effective_api_url}/api/v1/findings",
                    params=params,
                    headers={"Authorization": f"Bearer {jwt_token}"},
                    timeout=30.0
                )
                response.raise_for_status()
                findings = response.json()
    except Exception as e:
        rprint(f"[red]Error fetching report data: {str(e)}[/red]")
        raise typer.Abort()

    if not findings:
        rprint("[yellow]No findings found for the specified filters.[/yellow]")
        return

    # 3. Sorting
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
    type_order = {"SAST": 0, "SCA": 1, "IAC": 2, "SECRETS": 3, "CONTAINER": 4, "UNKNOWN": 5}
    
    findings.sort(key=lambda f: (
        f.get("repository_name", "").lower(),
        f.get("branch_name", "").lower(),
        type_order.get(f.get("scan_type", "UNKNOWN").upper(), 5),
        severity_order.get(f.get("severity", "UNKNOWN").upper(), 5)
    ))

    # 4. Handle Formats
    if format == ReportFormat.JSON:
        import json
        output_data = json.dumps(findings, indent=2)
        if output:
            with open(output, "w") as f:
                f.write(output_data)
            rprint(f"[green]Report saved to {output}[/green]")
        else:
            print(output_data)
            
    elif format == ReportFormat.TEXT:
        display_text_report(findings, current_repo, current_branch, include_description, include_mitigation, active_only)
        
    elif format == ReportFormat.MARKDOWN:
        md_content = generate_markdown_report(findings, current_repo, current_branch, include_description, include_mitigation, active_only)
        if output:
            with open(output, "w") as f:
                f.write(md_content)
            rprint(f"[green]Markdown report saved to {output}[/green]")
        else:
            print(md_content)
            
    elif format == ReportFormat.PDF:
        if not output:
            rprint("[red]Error: PDF format requires an output file path.[/red]")
            rprint("Please provide one using the [bold]--output / -o[/bold] flag.")
            raise typer.Abort()
        generate_pdf_report(findings, current_repo, current_branch, output, include_description, include_mitigation, active_only)
    else:
        rprint(f"[red]Error: Unsupported format '{format}'.[/red]")
        rprint("Supported formats are: [bold]text, json, markdown, pdf[/bold]")
        raise typer.Abort()

def display_text_report(findings, repo, branch, include_description, include_mitigation, active_only):
    table = Table(title=f"Security Findings: {repo} ({branch})")
    table.add_column("ID", style="dim")
    if not active_only:
        table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Type")
    table.add_column("Title")
    table.add_column("File")

    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim"
    }

    for f in findings:
        sev = f.get("severity", "UNKNOWN").upper()
        color = severity_colors.get(sev, "white")
        
        row_data = [f.get("finding_id", "N/A")]
        if not active_only:
            status = f.get("status", "Active")
            s_color = "green" if status == "Active" else "yellow" if status == "Mitigated" else "blue"
            row_data.append(f"[{s_color}]{status}[/{s_color}]")
            
        row_data.extend([
            f"[{color}]{sev}[/{color}]",
            f.get("scan_type", "N/A"),
            f.get("title", "N/A"),
            f"{f.get('file_path', 'N/A')}:{f.get('line_number', '')}"
        ])
        
        table.add_row(*row_data)
        if include_description and f.get("description"):
            table.add_row("", "", "", f"[dim]{f.get('description')}[/dim]", "")
        if include_mitigation and f.get("mitigation"):
            table.add_row("", "", "", f"[green]Mitigation: {f.get('mitigation')}[/green]", "")
    
    console.print(table)
    rprint(f"\n[bold]Total Findings:[/bold] {len(findings)}")

def generate_markdown_report(findings, repo, branch, include_description, include_mitigation, active_only):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    headers = ["Severity", "Type", "Title", "Location", "ID"]
    if not active_only:
        headers.insert(0, "Status")
    
    header_row = "| " + " | ".join(headers) + " |"
    separator_row = "| " + " | ".join([":---"] * len(headers)) + " |"

    lines = [
        f"# Gerion Security Report",
        f"**Repository:** {repo}  ",
        f"**Branch:** {branch}  ",
        f"**Date:** {now}  ",
        f"**Total Findings:** {len(findings)}",
        "",
        header_row,
        separator_row
    ]
    
    for f in findings:
        sev = f.get("severity", "UNKNOWN").upper()
        title = f.get("title", "N/A").replace("|", "\\|")
        file = f"{f.get('file_path', 'N/A')}:{f.get('line_number', '')}"
        fid = f.get("finding_id", "N/A")
        
        row = [sev, f.get("scan_type"), title, file, fid]
        if not active_only:
            row.insert(0, f.get("status", "Active"))
            
        lines.append("| " + " | ".join(row) + " |")
        
        if include_description and f.get("description"):
            lines.append(f"> **Description:** {f.get('description')}  ")
        if include_mitigation and f.get("mitigation"):
            lines.append(f"> **Mitigation:** {f.get('mitigation')}  ")
            
    return "\n".join(lines)

def generate_pdf_report(findings, repo, branch, output_path, include_description, include_mitigation, active_only):
    if not output_path:
        output_path = f"report_{repo}_{branch}_{datetime.now().strftime('%Y%m%d')}.pdf"
    
    try:
        from fpdf import FPDF
        
        # Calculate summary statistics
        stats = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNKNOWN": 0
        }
        for f in findings:
            sev = f.get("severity", "UNKNOWN").upper()
            stats[sev] = stats.get(sev, 0) + 1

        class GerionPDF(FPDF):
            def header(self):
                # Only on pages other than first? No, consistent header is fine
                self.set_font('helvetica', 'B', 24)
                self.set_text_color(0, 119, 190) # Gerion Blue
                self.cell(0, 15, 'GERION Security Report', border=0, ln=1, align='L')
                self.set_draw_color(0, 119, 190)
                self.set_line_width(0.5)
                self.line(10, 27, 200, 27)
                self.ln(12)

            def footer(self):
                self.set_y(-15)
                self.set_font('helvetica', 'I', 8)
                self.set_text_color(150)
                self.cell(0, 10, f'Generated by Gerion Security - Page {self.page_no()}/{{nb}}', 0, 0, 'C')

        pdf = GerionPDF()
        pdf.alias_nb_pages()
        pdf.add_page()
        
        # 1. Report Metadata
        pdf.set_fill_color(248, 249, 250)
        pdf.set_draw_color(222, 226, 230)
        pdf.set_font('helvetica', 'B', 12)
        pdf.set_text_color(33, 37, 41)
        pdf.cell(0, 10, ' Project Information', ln=1, fill=True, border='B')
        
        pdf.set_font('helvetica', '', 10)
        pdf.ln(2)
        col_width = 40
        pdf.set_font('helvetica', 'B', 10)
        pdf.cell(col_width, 7, ' Repository:', 0, 0)
        pdf.set_font('helvetica', '', 10)
        pdf.cell(0, 7, repo, 0, 1)
        
        pdf.set_font('helvetica', 'B', 10)
        pdf.cell(col_width, 7, ' Branch:', 0, 0)
        pdf.set_font('helvetica', '', 10)
        pdf.cell(0, 7, branch, 0, 1)
        
        pdf.set_font('helvetica', 'B', 10)
        pdf.cell(col_width, 7, ' Execution Date:', 0, 0)
        pdf.set_font('helvetica', '', 10)
        pdf.cell(0, 7, datetime.now().strftime("%B %d, %Y %H:%M:%S"), 0, 1)
        
        pdf.set_font('helvetica', 'B', 10)
        pdf.cell(col_width, 7, ' Report Scope:', 0, 0)
        pdf.set_font('helvetica', '', 10)
        scope = "Active Findings Only" if active_only else "All Findings (incl. Mitigated/FP)"
        pdf.cell(0, 7, scope, 0, 1)
        pdf.ln(10)

        # 2. Executive Summary (Parity with Frontend)
        pdf.set_font('helvetica', 'B', 12)
        pdf.cell(0, 10, ' Findings Summary', ln=1, fill=True, border='B')
        pdf.ln(5)
        
        # Grid for summary boxes
        pdf.set_font('helvetica', 'B', 9)
        spacing = 5
        box_width = (pdf.w - 20 - (spacing * 5)) / 6
        
        # Define colors for boxes
        sev_colors = {
            "CRITICAL": (33, 37, 41), # Dark
            "HIGH": (220, 53, 69),    # Red
            "MEDIUM": (253, 126, 20), # Orange
            "LOW": (13, 110, 253),    # Blue
            "INFO": (108, 117, 125),  # Gray
            "UNKNOWN": (200, 200, 200)     # Light Gray
        }
        
        current_x = pdf.get_x()
        for sev, count in stats.items():
            if sev == "UNKNOWN": continue # Combine or skip
            
            pdf.set_fill_color(*sev_colors.get(sev, (200, 200, 200)))
            pdf.set_text_color(255)
            
            # Draw box
            # Save current position
            x, y = pdf.get_x(), pdf.get_y()
            
            # Draw background and border
            pdf.cell(box_width, 15, "", border=1, ln=0, fill=True)
            
            # Reset pointer to start of box for text
            pdf.set_xy(x, y)
            
            # Draw text lines centered
            pdf.set_font('helvetica', 'B', 10)
            # Center vertically: (15 - 8) / 2 approx top padding? No, multi_cell starts at top.
            # Lets just do two cells manually for control
            pdf.cell(box_width, 7, str(count), border=0, ln=2, align='C')
            pdf.set_font('helvetica', 'B', 7)
            pdf.cell(box_width, 6, sev, border=0, ln=0, align='C')
            
            # Move to next box position
            pdf.set_xy(x + box_width + spacing, y)
        
        pdf.ln(25)

        # 3. Detailed Findings List
        pdf.set_font('helvetica', 'B', 12)
        pdf.set_text_color(0)
        pdf.cell(0, 10, ' Detailed Analysis', ln=1, fill=True, border='B')
        pdf.ln(5)

        for i, f in enumerate(findings, 1):
            # Check for page break
            if pdf.get_y() > 240:
                pdf.add_page()
            
            status = f.get("status", "Active")
            sev = f.get("severity", "UNKNOWN").upper()
            stype = f.get("scan_type", "N/A")
            title = f.get("title", "N/A")
            fid = f.get("finding_id", "N/A")
            location = f"{f.get('file_path', 'N/A')}:{f.get('line_number', '')}"
            
            # Header of the finding box
            pdf.set_fill_color(240, 240, 240)
            pdf.set_font('helvetica', 'B', 10)
            pdf.set_text_color(0, 119, 190)
            pdf.cell(0, 8, f" Finding #{i}: {title}", ln=1, fill=True, border='TLR')
            
            # Metadata row inside the box
            pdf.set_text_color(0)
            pdf.set_font('helvetica', 'B', 8)
            pdf.cell(30, 7, " Severity:", 'L', 0)
            
            # Severity Indicator
            pdf.set_fill_color(*sev_colors.get(sev, (200, 200, 200)))
            pdf.set_text_color(255)
            pdf.cell(20, 5, sev, border=0, ln=0, align='C', fill=True)
            
            pdf.set_text_color(0)
            pdf.cell(20, 7, "   Type:", 0, 0)
            pdf.set_font('helvetica', '', 8)
            pdf.cell(30, 7, stype, 0, 0)
            
            if not active_only:
                pdf.set_font('helvetica', 'B', 8)
                pdf.cell(20, 7, "  Status:", 0, 0)
                pdf.set_font('helvetica', '', 8)
                s_color = (40, 167, 69) if status == "Active" else (255, 193, 7) if status == "Mitigated" else (23, 162, 184)
                pdf.set_text_color(*s_color)
                pdf.cell(25, 7, status, 'R', 1)
                pdf.set_text_color(0)
            else:
                pdf.cell(0, 7, "", 'R', 1)

            # Location row
            import textwrap
            
            loc_text = location
            # Safe width 75 chars
            loc_lines = textwrap.wrap(loc_text, width=75, break_long_words=True, replace_whitespace=False)
            if not loc_lines: loc_lines = [""]
            
            pdf.set_font('helvetica', 'B', 8)
            pdf.cell(30, 7, " Location:", 'L', 0)
            
            pdf.set_font('helvetica', '', 7)
            pdf.cell(0, 7, loc_lines[0], 'R', 1)
            
            for line in loc_lines[1:]:
                pdf.cell(30, 5, "", 'L', 0)
                pdf.cell(0, 5, line, 'R', 1)
            
            # Explicit cursor reset for safety
            pdf.set_x(pdf.l_margin)
            
            # Description & Mitigation
            import textwrap
            
            if include_description and f.get("description"):
                desc_text = f.get("description") or ""
                # Wrap text to list of lines. 
                # Width 75 chars approx 150mm. + 30mm label = 180mm. Page width 190mm. Safe.
                desc_lines = textwrap.wrap(desc_text, width=75, break_long_words=True, replace_whitespace=False)
                
                if not desc_lines: desc_lines = [""]
                
                # Line 1: Label + Content
                pdf.set_font('helvetica', 'B', 8)
                pdf.cell(30, 5, " Description:", 'L', 0)
                
                pdf.set_font('helvetica', '', 8)
                pdf.cell(0, 5, desc_lines[0], 'R', 1)
                
                # Subsequent lines
                for line in desc_lines[1:]:
                    pdf.cell(30, 5, "", 'L', 0)
                    pdf.cell(0, 5, line, 'R', 1)
                
            if include_mitigation and f.get("mitigation"):
                mit_text = f.get("mitigation") or ""
                mit_lines = textwrap.wrap(mit_text, width=75, break_long_words=True, replace_whitespace=False)
                
                if not mit_lines: mit_lines = [""]
                
                pdf.set_fill_color(232, 245, 233)
                pdf.set_text_color(27, 94, 32)
                
                # Line 1
                pdf.set_font('helvetica', 'B', 8)
                pdf.cell(30, 5, " Remediation:", 'L', 0, fill=True)
                
                pdf.set_font('helvetica', 'I', 8)
                pdf.cell(0, 5, mit_lines[0], 'R', 1, fill=True)
                
                # Subsequent lines
                for line in mit_lines[1:]:
                    pdf.cell(30, 5, "", 'L', 0, fill=True)
                    pdf.cell(0, 5, line, 'R', 1, fill=True)
                    
                pdf.set_text_color(0)
            
            # Close the finding box
            pdf.cell(0, 2, "", 'T', 1) 
            pdf.ln(3)

        pdf.output(output_path)
        rprint(f"[green]PDF report successfully generated: {output_path}[/green]")

    except ImportError:
        rprint("[red]Error: fpdf2 library not found.[/red]")
        rprint("Please install it using: [bold]poetry add fpdf2[/bold]")
        raise typer.Abort()
    except Exception as e:
        rprint(f"[red]Error generating PDF report: {str(e)}[/red]")
        import traceback
        traceback.print_exc()
        raise typer.Abort()
