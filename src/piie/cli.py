"""
PII-Safe CLI

Command-line interface for PII detection and sanitization.
"""

import json
import sys
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table

from detectors import PIIDetector
from sanitizers import PIISanitizer, SanitizationAction, PseudonymizationEngine
from config import load_config

app = typer.Typer(
    name="piisafe",
    help="PII-Safe: Privacy Layer for Agentic AI Systems",
    add_completion=False,
)
console = Console()


def version_callback(value: bool):
    """Show version and exit."""
    if value:
        console.print("[bold]PII-Safe[/bold] version 1.0.0")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", callback=version_callback, help="Show version and exit"
    ),
):
    """PII-Safe CLI for detecting and sanitizing PII in text and files."""
    pass


@app.command("detect")
def detect_pii(
    input_file: Optional[Path] = typer.Option(
        None, "--input", "-i", help="Input file (JSON or text)"
    ),
    text: Optional[str] = typer.Option(
        None, "--text", "-t", help="Text to analyze directly"
    ),
    entity_types: Optional[List[str]] = typer.Option(
        None, "--entity-types", "-e", help="Filter by entity types (e.g., EMAIL, PHONE)"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file (default: stdout)"
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json, text"
    ),
):
    """
    Detect PII in text or files.

    Examples:
        piisafe detect -t "Contact john@example.com"
        piisafe detect -i data.jsonl -e EMAIL -e PHONE -o results.json
    """
    if not text and not input_file:
        console.print("[red]Error:[/red] Must specify --text or --input")
        raise typer.Exit(1)

    detector = PIIDetector()

    # Get input content
    if text:
        content = text
        content_type = "text"
    else:
        if not input_file.exists():
            console.print(f"[red]Error:[/red] File not found: {input_file}")
            raise typer.Exit(1)
        content = input_file.read_text()
        content_type = "file"

    # Detect PII
    matches = detector.detect(content)

    # Filter by entity types if specified
    if entity_types:
        matches = [m for m in matches if m.entity_type.value in entity_types]

    # Output results
    if format == "table":
        table = Table(title="PII Detection Results")
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="yellow")
        table.add_column("Position", style="green")
        table.add_column("Confidence", style="magenta")

        for match in matches:
            table.add_row(
                match.entity_type.value,
                match.value[:50] + ("..." if len(match.value) > 50 else ""),
                f"{match.start_pos}-{match.end_pos}",
                f"{match.confidence:.2f}",
            )

        console.print(table)
        console.print(f"\n[bold]Total:[/bold] {len(matches)} entities found")

    elif format == "json":
        result = {
            "entities_found": len(matches),
            "matches": [
                {
                    "entity_type": m.entity_type.value,
                    "value": m.value,
                    "start": m.start_pos,
                    "end": m.end_pos,
                    "confidence": m.confidence,
                }
                for m in matches
            ],
        }
        if output:
            output.write_text(json.dumps(result, indent=2))
            console.print(f"[green]Results written to[/green] {output}")
        else:
            console.print(json.dumps(result, indent=2))

    elif format == "text":
        lines = [f"{m.entity_type.value}: {m.value} ({m.start_pos}-{m.end_pos})" for m in matches]
        if output:
            output.write_text("\n".join(lines))
            console.print(f"[green]Results written to[/green] {output}")
        else:
            for line in lines:
                console.print(line)


@app.command("sanitize")
def sanitize_content(
    input_file: Optional[Path] = typer.Option(
        None, "--input", "-i", help="Input file (JSON or text)"
    ),
    text: Optional[str] = typer.Option(
        None, "--text", "-t", help="Text to sanitize directly"
    ),
    action: str = typer.Option(
        "redact", "--action", "-a", help="Action: redact, pseudonymize, allow, block"
    ),
    entity_types: Optional[List[str]] = typer.Option(
        None, "--entity-types", "-e", help="Entity types to sanitize"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file (default: stdout)"
    ),
    policy_file: Optional[Path] = typer.Option(
        None, "--policy", "-p", help="Policy YAML file"
    ),
):
    """
    Sanitize PII in text or files.

    Examples:
        piisafe sanitize -t "Email: john@example.com" -a redact
        piisafe sanitize -i logs.jsonl -a pseudonymize -o sanitized.jsonl
    """
    if not text and not input_file:
        console.print("[red]Error:[/red] Must specify --text or --input")
        raise typer.Exit(1)

    detector = PIIDetector()
    sanitizer = PIISanitizer(PseudonymizationEngine())

    try:
        sanitization_action = SanitizationAction(action)
    except ValueError:
        console.print(f"[red]Error:[/red] Invalid action: {action}")
        console.print("Valid actions: redact, pseudonymize, allow, block")
        raise typer.Exit(1)

    # Get input content
    if text:
        content = text
        is_json = False
    else:
        if not input_file.exists():
            console.print(f"[red]Error:[/red] File not found: {input_file}")
            raise typer.Exit(1)
        content = input_file.read_text()
        is_json = input_file.suffix in [".json", ".jsonl"]

    # Parse JSON if applicable
    if is_json:
        try:
            content = json.loads(content)
        except json.JSONDecodeError:
            pass  # Keep as string

    # Detect and sanitize
    if isinstance(content, str):
        matches = detector.detect(content)
        result = sanitizer.sanitize(content, matches, sanitization_action)
        sanitized = result.sanitized
        all_matches = matches
    else:
        sanitized, all_matches = sanitizer.sanitize_json_value(
            content, sanitization_action, detector
        )

    # Filter by entity types if specified
    if entity_types:
        all_matches = [m for m in all_matches if m.entity_type.value in entity_types]

    # Output
    if isinstance(sanitized, (dict, list)):
        output_text = json.dumps(sanitized, indent=2)
    else:
        output_text = sanitized

    if output:
        output.write_text(output_text)
        console.print(
            f"[green]Sanitized {len(all_matches)} entities[/green] -> {output}"
        )
    else:
        console.print(output_text)
        console.print(f"\n[bold]Sanitized {len(all_matches)} entities[/bold]")


@app.command("batch")
def batch_process(
    input_file: Path = typer.Option(..., "--input", "-i", help="Input file (JSONL)"),
    output_file: Path = typer.Option(..., "--output", "-o", help="Output file"),
    action: str = typer.Option("redact", "--action", "-a", help="Sanitization action"),
    entity_types: Optional[List[str]] = typer.Option(
        None, "--entity-types", "-e", help="Entity types to sanitize"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be processed without writing"
    ),
):
    """
    Batch process a JSONL file.

    Examples:
        piisafe batch -i logs.jsonl -o sanitized.jsonl -a redact
        piisafe batch -i data.jsonl -o out.jsonl --dry-run
    """
    if not input_file.exists():
        console.print(f"[red]Error:[/red] File not found: {input_file}")
        raise typer.Exit(1)

    detector = PIIDetector()
    sanitizer = PIISanitizer(PseudonymizationEngine())

    try:
        sanitization_action = SanitizationAction(action)
    except ValueError:
        console.print(f"[red]Error:[/red] Invalid action: {action}")
        raise typer.Exit(1)

    lines = input_file.read_text().strip().split("\n")
    total_entities = 0
    processed = 0

    if dry_run:
        console.print("[yellow]Dry run - no files will be written[/yellow]\n")

    output_lines = []
    for i, line in enumerate(lines):
        if not line.strip():
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError as e:
            console.print(f"[yellow]Warning:[/yellow] Line {i + 1}: Invalid JSON - {e}")
            continue

        # Sanitize
        sanitized, matches = sanitizer.sanitize_json_value(
            data, sanitization_action, detector
        )

        if entity_types:
            matches = [m for m in matches if m.entity_type.value in entity_types]

        total_entities += len(matches)
        processed += 1
        output_lines.append(json.dumps(sanitized))

        if dry_run:
            console.print(
                f"Line {i + 1}: {len(matches)} entities "
                f"({', '.join(set(m.entity_type.value for m in matches))})"
            )

    if not dry_run:
        output_file.write_text("\n".join(output_lines))
        console.print(
            f"[green]Processed {processed} lines, sanitized {total_entities} entities[/green]\n"
            f"Output: {output_file}"
        )
    else:
        console.print(
            f"\n[bold]Would process:[/bold] {processed} lines, "
            f"{total_entities} entities total"
        )


@app.command("policy")
def show_policy(
    policy_file: Optional[Path] = typer.Option(
        None, "--file", "-f", help="Policy YAML file"
    ),
    list_policies: bool = typer.Option(
        False, "--list", "-l", help="List all policies"
    ),
):
    """
    View and manage policies.

    Examples:
        piisafe policy -l
        piisafe policy -f config/policy.yaml
    """
    if policy_file:
        if not policy_file.exists():
            console.print(f"[red]Error:[/red] File not found: {policy_file}")
            raise typer.Exit(1)

        config = load_config(str(policy_file))
        console.print(f"\n[bold]Policy file:[/bold] {policy_file}\n")

        table = Table(title="Policies")
        table.add_column("Name", style="cyan")
        table.add_column("Entity Types", style="yellow")
        table.add_column("Action", style="green")

        for policy in config.get("policies", []):
            table.add_row(
                policy.get("name", "unnamed"),
                ", ".join(policy.get("entity_types", [])),
                policy.get("action", "unknown"),
            )

        console.print(table)

        console.print(f"\n[bold]Audit logging:[/bold] {config.get('audit_logging', False)}")
        console.print(f"[bold]Risk scoring:[/bold] {config.get('risk_scoring', False)}")

    elif list_policies:
        default_policy = Path("config/policy.yaml")
        if default_policy.exists():
            show_policy(default_policy, False)
        else:
            console.print("[yellow]No default policy found[/yellow]")
    else:
        console.print("Use --file to specify a policy or --list for default")


@app.command("stats")
def show_stats(
    text: Optional[str] = typer.Option(
        None, "--text", "-t", help="Analyze text directly"
    ),
    input_file: Optional[Path] = typer.Option(
        None, "--input", "-i", help="Analyze file"
    ),
):
    """
    Show PII statistics for content.

    Examples:
        piisafe stats -t "Contact: john@example.com, 555-1234"
        piisafe stats -i data.json
    """
    if not text and not input_file:
        console.print("[red]Error:[/red] Must specify --text or --input")
        raise typer.Exit(1)

    detector = PIIDetector()
    sanitizer = PIISanitizer(PseudonymizationEngine())

    if text:
        content = text
    else:
        content = input_file.read_text()

    matches = detector.detect(content)

    # Count by type
    type_counts = {}
    for match in matches:
        type_name = match.entity_type.value
        type_counts[type_name] = type_counts.get(type_name, 0) + 1

    risk_score = sanitizer.calculate_risk_score(matches)

    table = Table(title="PII Statistics")
    table.add_column("Entity Type", style="cyan")
    table.add_column("Count", style="green", justify="right")

    for type_name, count in sorted(type_counts.items()):
        table.add_row(type_name, str(count))

    table.add_row("TOTAL", str(len(matches)), style="bold")

    console.print(table)
    console.print(f"\n[bold]Risk Score:[/bold] {risk_score:.2f}/1.00")


if __name__ == "__main__":
    app()
