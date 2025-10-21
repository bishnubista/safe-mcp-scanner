"""Human-readable text reporter with colored console output.

Uses Rich library for formatting and colors.
"""

from collections import Counter
from typing import List
from io import StringIO

try:
    from rich.console import Console
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from .base import BaseReporter, ScanResults, Finding


class TextReporter(BaseReporter):
    """Generate human-readable console output with colors."""

    @property
    def format_name(self) -> str:
        """Name of the output format."""
        return "text"

    @property
    def file_extension(self) -> str:
        """File extension for this format."""
        return ".txt"

    SEVERITY_COLORS = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
    }

    SEVERITY_ICONS = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
    }

    def format_results(self, results: ScanResults) -> str:
        """Format scan results as colored text.

        Args:
            results: Scan results to format

        Returns:
            Formatted text output
        """
        if RICH_AVAILABLE:
            return self._format_with_rich(results)
        else:
            return self._format_plain(results)

    def _format_with_rich(self, results: ScanResults) -> str:
        """Format using Rich library for colors and formatting."""
        # Create console that captures output
        output = StringIO()
        console = Console(file=output, force_terminal=True, width=80)

        # Header
        console.print("\n[bold cyan]🔍 MCP Security Scan Results[/bold cyan]")
        console.print("━" * 60)

        # Summary
        self._print_summary_rich(console, results)
        console.print("━" * 60)

        # Findings
        if results.findings:
            self._print_findings_rich(console, results.findings)
        else:
            console.print("\n[green]✅ No security issues found![/green]\n")

        # Footer
        console.print("━" * 60)
        self._print_footer_rich(console, results)
        console.print()

        return output.getvalue()

    def _print_summary_rich(self, console: Console, results: ScanResults):
        """Print summary statistics with Rich formatting."""
        severity_counts = Counter(f.severity.lower() for f in results.findings)

        console.print("\n[bold]📊 Summary[/bold]")
        console.print(f"  Total Findings: {len(results.findings)}")

        for severity in ["critical", "high", "medium", "low"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                icon = self.SEVERITY_ICONS[severity]
                color = self.SEVERITY_COLORS[severity]
                console.print(f"  {icon} {severity.capitalize()}: [{color}]{count}[/{color}]")

        console.print(f"  Files Scanned: {len(results.scanned_files)}")
        console.print(f"  Duration: {results.scan_duration:.2f}s")

    def _print_findings_rich(self, console: Console, findings: List[Finding]):
        """Print detailed findings with Rich formatting."""
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(
            findings,
            key=lambda f: (severity_order.get(f.severity.lower(), 4), str(f.file_path))
        )

        for i, finding in enumerate(sorted_findings, 1):
            if i > 1:
                console.print()
            self._print_finding_rich(console, finding)

    def _print_finding_rich(self, console: Console, finding: Finding):
        """Print a single finding with Rich formatting."""
        severity = finding.severity.lower()
        icon = self.SEVERITY_ICONS.get(severity, "⚪")
        color = self.SEVERITY_COLORS.get(severity, "white")

        # Title with location
        location = str(finding.file_path)
        if finding.line_number:
            location += f":{finding.line_number}"
            if finding.column_number:
                location += f":{finding.column_number}"

        console.print(f"{icon} [{color}]{severity.upper()}[/{color}]: {finding.message}")
        console.print(f"  └─ File: {location}")
        console.print(f"  └─ ID: {finding.technique_id}")

        # Description
        if finding.description:
            console.print(f"\n  [dim]Description:[/dim]")
            for line in finding.description.split('\n'):
                console.print(f"    {line}")

        # Recommendation
        if finding.recommendation:
            console.print(f"\n  [green]💡 Recommendation:[/green]")
            for line in finding.recommendation.split('\n'):
                console.print(f"    {line}")

        # Source code context
        if finding.source_code:
            console.print(f"\n  [dim]Source:[/dim]")
            for line in finding.source_code.split('\n'):
                console.print(f"    [dim]{line}[/dim]")

        # Confidence
        if finding.confidence < 1.0:
            console.print(f"\n  [dim]Confidence: {finding.confidence:.0%}[/dim]")

    def _print_footer_rich(self, console: Console, results: ScanResults):
        """Print footer with verdict."""
        critical_count = sum(1 for f in results.findings if f.severity.lower() == "critical")
        high_count = sum(1 for f in results.findings if f.severity.lower() == "high")

        if critical_count > 0:
            console.print(
                f"\n[red bold]❌ Scan failed: {critical_count} critical issue(s) found[/red bold]"
            )
        elif high_count > 0:
            console.print(
                f"\n[yellow bold]⚠️  Warning: {high_count} high severity issue(s) found[/yellow bold]"
            )
        else:
            console.print("\n[green bold]✅ Scan passed[/green bold]")

    def _format_plain(self, results: ScanResults) -> str:
        """Format as plain text without colors (fallback when Rich not available)."""
        output = []

        # Header
        output.append("\n" + "=" * 60)
        output.append("MCP Security Scan Results")
        output.append("=" * 60)

        # Summary
        severity_counts = Counter(f.severity.lower() for f in results.findings)
        output.append("\nSummary:")
        output.append(f"  Total Findings: {len(results.findings)}")

        for severity in ["critical", "high", "medium", "low"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                output.append(f"  {severity.capitalize()}: {count}")

        output.append(f"  Files Scanned: {len(results.scanned_files)}")
        output.append(f"  Duration: {results.scan_duration:.2f}s")
        output.append("-" * 60)

        # Findings
        if results.findings:
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            sorted_findings = sorted(
                results.findings,
                key=lambda f: (severity_order.get(f.severity.lower(), 4), str(f.file_path))
            )

            for finding in sorted_findings:
                output.append("")
                output.extend(self._format_finding_plain(finding))
        else:
            output.append("\nNo security issues found!")

        # Footer
        output.append("-" * 60)
        critical_count = sum(1 for f in results.findings if f.severity.lower() == "critical")
        high_count = sum(1 for f in results.findings if f.severity.lower() == "high")

        if critical_count > 0:
            output.append(f"\nScan failed: {critical_count} critical issue(s) found")
        elif high_count > 0:
            output.append(f"\nWarning: {high_count} high severity issue(s) found")
        else:
            output.append("\nScan passed")

        output.append("")
        return "\n".join(output)

    def _format_finding_plain(self, finding: Finding) -> List[str]:
        """Format a single finding as plain text."""
        lines = []

        # Title
        location = str(finding.file_path)
        if finding.line_number:
            location += f":{finding.line_number}"
            if finding.column_number:
                location += f":{finding.column_number}"

        lines.append(f"{finding.severity.upper()}: {finding.message}")
        lines.append(f"  File: {location}")
        lines.append(f"  ID: {finding.technique_id}")

        # Description
        if finding.description:
            lines.append(f"\n  Description:")
            for line in finding.description.split('\n'):
                lines.append(f"    {line}")

        # Recommendation
        if finding.recommendation:
            lines.append(f"\n  Recommendation:")
            for line in finding.recommendation.split('\n'):
                lines.append(f"    {line}")

        # Source code
        if finding.source_code:
            lines.append(f"\n  Source:")
            for line in finding.source_code.split('\n'):
                lines.append(f"    {line}")

        # Confidence
        if finding.confidence < 1.0:
            lines.append(f"\n  Confidence: {finding.confidence:.0%}")

        return lines
