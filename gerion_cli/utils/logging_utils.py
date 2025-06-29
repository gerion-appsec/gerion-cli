import typer
import logging
from enum import Enum
from typing import Optional, List, Dict
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm

# Global console instance
console = Console()

class LogLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class OutputFormat(str, Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"

class GerionLogger:
    def __init__(self, log_level: LogLevel = LogLevel.INFO):
        self.log_level = log_level
        self.logger = logging.getLogger("gerion-cli")
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Remove existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Add Rich handler for beautiful formatting
        rich_handler = RichHandler(
            console=console,
            show_time=False,
            show_path=False,
            markup=True,
            rich_tracebacks=False
        )
        rich_handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(rich_handler)
    
    def debug(self, message: str):
        self.logger.debug(f"[dim]{message}[/dim]")
    
    def info(self, message: str):
        self.logger.info(f"[blue]{message}[/blue]")
    
    def warning(self, message: str):
        self.logger.warning(f"[yellow]⚠️  {message}[/yellow]")
    
    def error(self, message: str):
        self.logger.error(f"[red]❌ {message}[/red]")
    
    def success(self, message: str):
        console.print(f"[green]✅ {message}[/green]")
    
    def panel(self, title: str, content: str, style: str = "blue"):
        panel = Panel(content, title=title, style=style)
        console.print(panel)
    
    def table(self, title: str, headers: list, rows: list):
        table = Table(title=title)
        for header in headers:
            table.add_column(header)
        for row in rows:
            table.add_row(*row)
        console.print(table)
    
    def progress(self, description: str = "Processing..."):
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        )

# Global logger instance
_logger: Optional[GerionLogger] = None

def get_logger() -> GerionLogger:
    global _logger
    if _logger is None:
        _logger = GerionLogger()
    return _logger

def set_log_level(log_level: LogLevel):
    global _logger
    _logger = GerionLogger(log_level)

def debug(message: str):
    get_logger().debug(message)

def info(message: str):
    get_logger().info(message)

def warning(message: str):
    get_logger().warning(message)

def error(message: str):
    get_logger().error(message)

def success(message: str):
    get_logger().success(message)

def panel(title: str, content: str, style: str = "blue"):
    get_logger().panel(title, content, style)

def table(title: str, headers: list, rows: list):
    get_logger().table(title, headers, rows)

def progress(description: str = "Processing..."):
    return get_logger().progress(description)

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
        table.add_column("Severity", style="bold", width=8)
        table.add_column("Title", style="bold", width=35)
        table.add_column("File:Line", style="cyan", width=25)
        table.add_column("Description", width=45)
        
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
                f"{finding.get('file_path', 'N/A')}:{finding.get('line_number', 'N/A')}",
                finding.get('description', 'N/A')[:42] + "..." if len(finding.get('description', '')) > 45 else finding.get('description', 'N/A')
            )
    
    else:  # SCA
        table.add_column("Severity", style="bold", width=8)
        table.add_column("CVE", style="bold", width=15)
        table.add_column("Component", style="cyan", width=30)
        table.add_column("File", style="cyan", width=25)
        table.add_column("Description", width=35)
        
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
                finding.get('file_path', 'N/A'),
                finding.get('description', 'N/A')[:32] + "..." if len(finding.get('description', '')) > 35 else finding.get('description', 'N/A')
            )
    
    console.print(table) 