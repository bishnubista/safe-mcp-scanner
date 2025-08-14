"""Command-line interface for the SAFE-MCP Scanner."""

import sys
from pathlib import Path
from typing import Optional, List

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .scanner import Scanner
from .config import Config, load_config


console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="safe-mcp-scan")
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    help="Configuration file path",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-error output")
@click.pass_context
def cli(ctx: click.Context, config: Optional[Path], verbose: bool, quiet: bool) -> None:
    """SAFE-MCP Scanner: Vulnerability scanner for MCP servers.
    
    Implements the SAFE-MCP framework to detect security issues in
    Model Context Protocol (MCP) server implementations.
    """
    ctx.ensure_object(dict)
    
    # Load configuration
    try:
        ctx.obj["config"] = load_config(config)
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)
    
    # Set up logging level
    if quiet:
        ctx.obj["log_level"] = "ERROR"
    elif verbose:
        ctx.obj["log_level"] = "DEBUG"
    else:
        ctx.obj["log_level"] = "INFO"


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path (default: stdout)",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "sarif", "text"], case_sensitive=False),
    default="json",
    help="Output format",
)
@click.option(
    "--techniques",
    "-t",
    multiple=True,
    help="Specific SAFE-MCP techniques to run (e.g., SAFE-T1001)",
)
@click.option(
    "--exclude-techniques",
    "-x",
    multiple=True,
    help="SAFE-MCP techniques to exclude",
)
@click.option(
    "--include",
    multiple=True,
    help="File patterns to include (glob syntax)",
)
@click.option(
    "--exclude",
    multiple=True,
    help="File patterns to exclude (glob syntax)",
)
@click.option(
    "--fail-on",
    type=click.Choice(["any", "high", "critical"], case_sensitive=False),
    help="Exit with non-zero code on specified severity levels",
)
@click.option(
    "--no-progress",
    is_flag=True,
    help="Disable progress reporting",
)
@click.pass_context
def scan(
    ctx: click.Context,
    path: Path,
    output: Optional[Path],
    format: str,
    techniques: List[str],
    exclude_techniques: List[str],
    include: List[str],
    exclude: List[str],
    fail_on: Optional[str],
    no_progress: bool,
) -> None:
    """Scan a directory or file for MCP security vulnerabilities.
    
    PATH: Directory or file to scan for vulnerabilities
    """
    config: Config = ctx.obj["config"]
    
    # Override config with CLI options
    if techniques:
        config.enabled_techniques = list(techniques)
    if exclude_techniques:
        config.disabled_techniques = list(exclude_techniques)
    if include:
        config.include_patterns = list(include)
    if exclude:
        config.exclude_patterns = list(exclude)
    if fail_on:
        config.fail_on_severity = fail_on
    
    # Initialize scanner
    scanner = Scanner(config)
    
    try:
        # Run scan with progress reporting
        # Don't show progress when outputting to stdout in JSON/SARIF format
        show_progress = not no_progress and ctx.obj["log_level"] == "INFO" and (output or format == "text")
        
        if show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning for vulnerabilities...", total=None)
                results = scanner.scan(path)
                progress.update(task, completed=True)
        else:
            results = scanner.scan(path)
        
        # Generate output
        output_content = scanner.format_results(results, format)
        
        # Write output
        if output:
            output.write_text(output_content)
            console.print(f"[green]Results written to {output}[/green]")
        else:
            # For JSON/SARIF, output directly without rich formatting
            if format in ["json", "sarif"]:
                click.echo(output_content)
            else:
                console.print(output_content)
        
        # Handle exit codes
        if config.fail_on_severity and results.has_findings_at_severity(config.fail_on_severity):
            console.print(f"[red]Exiting with error due to {config.fail_on_severity} severity findings[/red]")
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        if ctx.obj["log_level"] == "DEBUG":
            console.print_exception()
        sys.exit(1)


@cli.command()
@click.option(
    "--list-techniques",
    is_flag=True,
    help="List available SAFE-MCP techniques",
)
@click.option(
    "--show-config",
    is_flag=True,
    help="Show current configuration",
)
@click.pass_context
def info(ctx: click.Context, list_techniques: bool, show_config: bool) -> None:
    """Display information about the scanner and available techniques."""
    config: Config = ctx.obj["config"]
    
    if list_techniques:
        scanner = Scanner(config)
        techniques = scanner.get_available_techniques()
        
        console.print("[bold]Available SAFE-MCP Techniques:[/bold]")
        for technique_id, technique in techniques.items():
            console.print(f"  {technique_id}: {technique.name}")
            console.print(f"    {technique.description}")
            console.print()
    
    if show_config:
        console.print("[bold]Current Configuration:[/bold]")
        console.print(config.model_dump_json(indent=2))


@cli.command()
@click.argument("config_path", type=click.Path(path_type=Path))
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing configuration file",
)
def init_config(config_path: Path, force: bool) -> None:
    """Create a new configuration file with default settings.
    
    CONFIG_PATH: Path where the configuration file will be created
    """
    if config_path.exists() and not force:
        console.print(f"[red]Configuration file already exists: {config_path}[/red]")
        console.print("Use --force to overwrite")
        sys.exit(1)
    
    # Create default config
    default_config = Config()
    
    # Write to file
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(default_config.model_dump_json(indent=2))
    
    console.print(f"[green]Configuration file created: {config_path}[/green]")


def main() -> None:
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()