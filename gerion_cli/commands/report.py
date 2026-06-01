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
from gerion_cli.core.logging import info, error, warning, success
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
    output_file: Optional[str] = typer.Option(None, "--output-file", "-o", help="Output file path"),
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

    effective_api_url = api_url
    if not effective_api_url:
        error("API URL not provided. Please set GERION_API_URL or use --api-url.")
        raise typer.Abort()
        
    effective_client_id = client_id or CLIENT_ID
    api_key_string = SecretString.from_typer_option(api_key)

    # 1. Authentication
    # We use the M2M authentication flow to get a JWT token
    if not api_key_string:
        error("GERION_API_KEY environment variable is not set.")
        info("Please set your API key to authenticate.")
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
        warning("Could not detect a git repository. Using 'local' context.")
    
    info(f"Generating report for: {current_repo} ({current_branch})")
    
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
            with httpx.Client(verify=os.environ.get('GERION_CA_BUNDLE', True)) as client:
                response = client.get(
                    f"{effective_api_url}/api/v1/reporting/findings",
                    params=params,
                    headers={"Authorization": f"Bearer {jwt_token}"},
                    timeout=30.0
                )
                response.raise_for_status()
                findings = response.json()
    except Exception as e:
        error(f"Error fetching report data: {str(e)}")
        raise typer.Abort()

    if not findings:
        warning("No findings found for the specified filters.")
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
        if output_file:
            with open(output_file, "w") as f:
                f.write(output_data)
            success(f"Report saved to {output_file}")
        else:
            print(output_data)
            
    elif format == ReportFormat.TEXT:
        display_text_report(findings, current_repo, current_branch, include_description, include_mitigation, active_only)
        
    elif format == ReportFormat.MARKDOWN:
        md_content = generate_markdown_report(findings, current_repo, current_branch, include_description, include_mitigation, active_only)
        if output_file:
            with open(output_file, "w") as f:
                f.write(md_content)
            success(f"Markdown report saved to {output_file}")
        else:
            print(md_content)
            
    elif format == ReportFormat.PDF:
        if not output_file:
            error("PDF format requires an output file path.")
            info("Please provide one using the --output-file / -o flag.")
            raise typer.Abort()
        generate_pdf_report(findings, current_repo, current_branch, output_file, include_description, include_mitigation, active_only)
    else:
        error(f"Unsupported format '{format}'.")
        info("Supported formats are: text, json, markdown, pdf")
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
        n_prefix = len(row_data) - 2
        if include_description and f.get("description"):
            table.add_row(*[""] * n_prefix, f"[dim]{f.get('description')}[/dim]", "")
        if include_mitigation and f.get("mitigation"):
            table.add_row(*[""] * n_prefix, f"[green]Mitigation: {f.get('mitigation')}[/green]", "")
    
    console.print(table)
    info(f"Total Findings: {len(findings)}")

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
    import os

    def find_system_fonts():
        families = [
            {
                "name": "LiberationSans",
                "regular": "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
                "bold": "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
                "italic": "/usr/share/fonts/truetype/liberation/LiberationSans-Italic.ttf",
                "bold_italic": "/usr/share/fonts/truetype/liberation/LiberationSans-BoldItalic.ttf",
            },
            {
                "name": "DejaVuSans",
                "regular": "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                "bold": "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                "italic": "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf",
                "bold_italic": "/usr/share/fonts/truetype/dejavu/DejaVuSans-BoldOblique.ttf",
            },
            {
                "name": "ArialUnicode",
                "regular": "/Library/Fonts/Arial.ttf",
                "bold": "/Library/Fonts/Arial Bold.ttf",
                "italic": "/Library/Fonts/Arial Italic.ttf",
                "bold_italic": "/Library/Fonts/Arial Bold Italic.ttf",
            },
            {
                "name": "ArialUnicodeSupplemental",
                "regular": "/System/Library/Fonts/Supplemental/Arial.ttf",
                "bold": "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
                "italic": "/System/Library/Fonts/Supplemental/Arial Italic.ttf",
                "bold_italic": "/System/Library/Fonts/Supplemental/Arial Bold Italic.ttf",
            },
            {
                "name": "ArialWindows",
                "regular": "C:\\Windows\\Fonts\\arial.ttf",
                "bold": "C:\\Windows\\Fonts\\arialbd.ttf",
                "italic": "C:\\Windows\\Fonts\\ariali.ttf",
                "bold_italic": "C:\\Windows\\Fonts\\arialbi.ttf",
            }
        ]
        for family in families:
            if (os.path.exists(family["regular"]) and 
                os.path.exists(family["bold"]) and 
                os.path.exists(family["italic"]) and 
                os.path.exists(family["bold_italic"])):
                return family
        return None

    system_font_family = find_system_fonts()
    font_family = "custom_sans" if system_font_family else "helvetica"

    def sanitize_latin1(text: str) -> str:
        if not text:
            return ""
        # If we are using core Helvetica, we must sanitize to Latin-1
        if font_family == "helvetica":
            replacements = {
                "\u2014": "-",   # em dash
                "\u2013": "-",   # en dash
                "\u2018": "'",   # left single quote
                "\u2019": "'",   # right single quote
                "\u201c": '"',   # left double quote
                "\u201d": '"',   # right double quote
                "\u2022": "*",   # bullet
                "\u2026": "...", # ellipsis
                "\u20ac": "EUR", # euro symbol
                "\u00a0": " ",   # non-breaking space
            }
            for orig, rep in replacements.items():
                text = text.replace(orig, rep)
            return text.encode("latin-1", errors="ignore").decode("latin-1")
        # Unicode-capable fonts do not require sanitization
        return text

    repo = sanitize_latin1(repo)
    branch = sanitize_latin1(branch)

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
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                if font_family == "custom_sans":
                    self.add_font("custom_sans", style="", fname=system_font_family["regular"])
                    self.add_font("custom_sans", style="B", fname=system_font_family["bold"])
                    self.add_font("custom_sans", style="I", fname=system_font_family["italic"])
                    self.add_font("custom_sans", style="BI", fname=system_font_family["bold_italic"])

            def set_font(self, family_name, style="", size=0):
                if family_name.lower() == "helvetica" and font_family == "custom_sans" and "custom_sans" in self.fonts:
                    family_name = "custom_sans"
                super().set_font(family_name, style, size)

            def header(self):
                # Check if logo path exists and draw it
                logo_path = os.environ.get("GERION_LOGO_PATH", "")
                if os.path.exists(logo_path):
                    self.image(logo_path, x=10, y=9, w=13)
                    self.set_xy(26, 11)
                else:
                    self.set_xy(10, 11)
                
                self.set_font('helvetica', 'B', 22)
                self.set_text_color(21, 87, 121) # Gerion Dark Blue (#155779)
                self.cell(0, 10, 'GERION Security Report', border=0, ln=1, align='L')
                self.set_draw_color(21, 87, 121)
                self.set_line_width(0.5)
                self.line(10, 26, 200, 26)
                self.ln(8)

            def footer(self):
                self.set_y(-15)
                self.set_font('helvetica', 'I', 8)
                self.set_text_color(148, 163, 184) # Slate-400
                self.cell(0, 10, f'Generated by Gerion Security - Page {self.page_no()}/{{nb}}', 0, 0, 'C')

        pdf = GerionPDF()
        pdf.alias_nb_pages()
        pdf.add_page()
        
        # 1. Report Metadata
        pdf.set_fill_color(248, 250, 252) # Slate-50
        pdf.set_draw_color(226, 232, 240) # Slate-200
        pdf.set_font('helvetica', 'B', 11)
        pdf.set_text_color(30, 41, 59) # Slate-800
        pdf.cell(0, 9, ' Project Information', ln=1, fill=True, border='B')
        
        pdf.set_font('helvetica', '', 9)
        pdf.ln(1)
        col_width = 40
        
        pdf.set_font('helvetica', 'B', 9)
        pdf.set_text_color(71, 85, 105) # Slate-600
        pdf.cell(col_width, 6, ' Repository:', 0, 0)
        pdf.set_font('helvetica', '', 9)
        pdf.set_text_color(51, 65, 85) # Slate-700
        pdf.cell(0, 6, repo, 0, 1)
        
        pdf.set_font('helvetica', 'B', 9)
        pdf.set_text_color(71, 85, 105)
        pdf.cell(col_width, 6, ' Branch:', 0, 0)
        pdf.set_font('helvetica', '', 9)
        pdf.set_text_color(51, 65, 85)
        pdf.cell(0, 6, branch, 0, 1)
        
        pdf.set_font('helvetica', 'B', 9)
        pdf.set_text_color(71, 85, 105)
        pdf.cell(col_width, 6, ' Execution Date:', 0, 0)
        pdf.set_font('helvetica', '', 9)
        pdf.set_text_color(51, 65, 85)
        pdf.cell(0, 6, datetime.now().strftime("%B %d, %Y %H:%M:%S"), 0, 1)
        
        pdf.set_font('helvetica', 'B', 9)
        pdf.set_text_color(71, 85, 105)
        pdf.cell(col_width, 6, ' Report Scope:', 0, 0)
        pdf.set_font('helvetica', '', 9)
        pdf.set_text_color(51, 65, 85)
        scope = "Active Findings Only" if active_only else "All Findings (incl. Mitigated/FP)"
        pdf.cell(0, 6, scope, 0, 1)
        pdf.ln(8)

        # 2. Executive Summary
        pdf.set_fill_color(248, 250, 252)
        pdf.set_draw_color(226, 232, 240)
        pdf.set_font('helvetica', 'B', 11)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 9, ' Findings Summary', ln=1, fill=True, border='B')
        pdf.ln(4)
        
        # Grid for summary boxes
        spacing = 4
        box_width = (pdf.w - 20 - (spacing * 5)) / 6
        
        # Define colors for boxes
        sev_colors = {
            "CRITICAL": (15, 23, 42), # Dark Slate (900)
            "HIGH": (220, 53, 69),    # Red
            "MEDIUM": (249, 115, 22), # Orange (500)
            "LOW": (59, 130, 246),    # Blue (500)
            "INFO": (100, 116, 139),  # Gray (500)
            "UNKNOWN": (203, 213, 225) # Slate (300)
        }
        
        for sev, count in stats.items():
            if sev == "UNKNOWN": continue
            
            pdf.set_fill_color(*sev_colors.get(sev, (200, 200, 200)))
            pdf.set_text_color(255)
            
            x, y = pdf.get_x(), pdf.get_y()
            
            pdf.set_draw_color(226, 232, 240)
            pdf.cell(box_width, 14, "", border=1, ln=0, fill=True)
            
            pdf.set_xy(x, y)
            
            pdf.set_font('helvetica', 'B', 10)
            pdf.cell(box_width, 7, str(count), border=0, ln=2, align='C')
            pdf.set_font('helvetica', 'B', 6.5)
            pdf.cell(box_width, 5, sev, border=0, ln=0, align='C')
            
            pdf.set_xy(x + box_width + spacing, y)
        
        pdf.ln(20)

        # 3. Detailed Findings List
        pdf.set_fill_color(248, 250, 252)
        pdf.set_draw_color(226, 232, 240)
        pdf.set_font('helvetica', 'B', 11)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 9, ' Detailed Analysis', ln=1, fill=True, border='B')
        pdf.ln(4)

        pdf.set_draw_color(226, 232, 240) # soft border

        for i, f in enumerate(findings, 1):
            status = f.get("status", "Active")
            sev = f.get("severity", "UNKNOWN").upper()
            stype = sanitize_latin1(f.get("scan_type", "N/A"))
            title = sanitize_latin1(f.get("title", "N/A"))
            fid = f.get("finding_id", "N/A")
            location = sanitize_latin1(f"{f.get('file_path', 'N/A')}:{f.get('line_number', '')}")
            
            import textwrap
            
            loc_lines = textwrap.wrap(location, width=75, break_long_words=True)
            if not loc_lines: loc_lines = [""]
            
            desc_lines = []
            if include_description and f.get("description"):
                desc_text = sanitize_latin1(f.get("description") or "")
                for block in desc_text.splitlines():
                    if not block.strip():
                        desc_lines.append("")
                    else:
                        desc_lines.extend(textwrap.wrap(block, width=75, break_long_words=True))
                        
            mit_lines = []
            if include_mitigation and f.get("mitigation"):
                mit_text = sanitize_latin1(f.get("mitigation") or "")
                for block in mit_text.splitlines():
                    if not block.strip():
                        mit_lines.append("")
                    else:
                        mit_lines.extend(textwrap.wrap(block, width=75, break_long_words=True))
            
            # Height calculation
            card_height = 8 + 7  # Header + Metadata row
            card_height += len(loc_lines) * 5 + 1
            if desc_lines:
                card_height += len(desc_lines) * 5
            if mit_lines:
                card_height += len(mit_lines) * 5
            card_height += 5  # closing line + spacing
            
            # Page Break check (if it doesn't fit on page, trigger page break)
            page_top_y = 29.0
            page_bottom_y = 275.0
            max_usable_height = page_bottom_y - page_top_y  # 246.0 mm

            if pdf.get_y() > page_top_y + 1:
                if card_height <= max_usable_height:
                    if pdf.get_y() + card_height > page_bottom_y:
                        pdf.add_page()
                else:
                    if page_bottom_y - pdf.get_y() < 50:
                        pdf.add_page()
                
            # Header of the finding box
            pdf.set_fill_color(248, 250, 252) # Soft Slate-50
            pdf.set_font('helvetica', 'B', 9.5)
            pdf.set_text_color(30, 41, 59) # Slate-800
            pdf.cell(0, 8, f" Finding #{i}: {title}", ln=1, fill=True, border='TLR')
            
            # Metadata row inside the box
            pdf.set_text_color(71, 85, 105) # Slate-600
            pdf.set_font('helvetica', 'B', 8)
            pdf.cell(30, 7, " Severity:", 'L', 0)
            
            # Severity Indicator
            pdf.set_fill_color(*sev_colors.get(sev, (200, 200, 200)))
            pdf.set_text_color(255)
            pdf.cell(20, 5, f" {sev} ", border=0, ln=0, align='C', fill=True)
            
            pdf.set_text_color(71, 85, 105)
            pdf.cell(20, 7, "   Type:", 0, 0)
            pdf.set_font('helvetica', '', 8)
            pdf.set_text_color(51, 65, 85) # Slate-700
            pdf.cell(30, 7, stype, 0, 0)
            
            if not active_only:
                pdf.set_font('helvetica', 'B', 8)
                pdf.set_text_color(71, 85, 105)
                pdf.cell(20, 7, "  Status:", 0, 0)
                pdf.set_font('helvetica', '', 8)
                s_color = (34, 197, 94) if status == "Active" else (234, 179, 8) if status == "Mitigated" else (100, 116, 139)
                pdf.set_text_color(*s_color)
                pdf.cell(25, 7, status, 'R', 1)
                pdf.set_text_color(51, 65, 85)
            else:
                pdf.cell(0, 7, "", 'R', 1)

            # Location row
            pdf.set_font('helvetica', 'B', 8)
            pdf.set_text_color(71, 85, 105)
            pdf.cell(30, 6, " Location:", 'L', 0)
            
            pdf.set_font('helvetica', '', 7.5)
            pdf.set_text_color(51, 65, 85)
            pdf.cell(0, 6, loc_lines[0], 'R', 1)
            
            for line in loc_lines[1:]:
                pdf.cell(30, 5, "", 'L', 0)
                pdf.cell(0, 5, line, 'R', 1)
            
            pdf.set_x(pdf.l_margin)
            
            if include_description and desc_lines:
                pdf.set_font('helvetica', 'B', 8)
                pdf.set_text_color(71, 85, 105)
                pdf.cell(30, 5, " Description:", 'L', 0)
                
                pdf.set_font('helvetica', '', 8)
                pdf.set_text_color(51, 65, 85)
                pdf.cell(0, 5, desc_lines[0], 'R', 1)
                
                for line in desc_lines[1:]:
                    pdf.cell(30, 5, "", 'L', 0)
                    pdf.cell(0, 5, line, 'R', 1)
                
            if include_mitigation and mit_lines:
                # Soft green background for remediation note box
                pdf.set_fill_color(240, 253, 244) # Emerald-50
                pdf.set_text_color(21, 128, 61) # Emerald-700
                
                pdf.set_font('helvetica', 'B', 8)
                pdf.cell(30, 5, " Remediation:", 'L', 0, fill=True)
                
                pdf.set_font('helvetica', 'I', 8)
                pdf.cell(0, 5, mit_lines[0], 'R', 1, fill=True)
                
                for line in mit_lines[1:]:
                    pdf.cell(30, 5, "", 'L', 0, fill=True)
                    pdf.cell(0, 5, line, 'R', 1, fill=True)
                    
                pdf.set_text_color(51, 65, 85)
            
            # Close the finding box
            pdf.cell(0, 2, "", 'T', 1) 
            pdf.ln(3)

        pdf.output(output_path)
        success(f"PDF report successfully generated: {output_path}")

    except ImportError:
        error("fpdf2 library not found.")
        info("Please install it using: poetry add fpdf2")
        raise typer.Abort()
    except Exception as e:
        error(f"Error generating PDF report: {str(e)}")
        import traceback
        traceback.print_exc()
        raise typer.Abort()
