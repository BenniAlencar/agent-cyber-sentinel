"""
Command-line Interface for Agent Cyber Sentinel.
Provides terminal scanning, tool inspection, secret redaction, and POD-9 envelope verification.
Governed by Benni Master OS v9.4 (Skill 63 Cyber Sentinel OS).
"""

from __future__ import annotations

import json
from typing import Optional
import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cyber_sentinel.core.envelope import Pod9ProofEnvelope
from cyber_sentinel.core.models import SecurityThreatLevel
from cyber_sentinel.shield import CyberSentinel
from cyber_sentinel.version import __version__

console = Console()


def print_banner() -> None:
    banner = f"""[bold yellow][SHIELD] Agent Cyber Sentinel v{__version__}[/bold yellow]
[cyan]Tier-0 Zero-Trust Runtime Security Shield for AI Agents & MCP Servers[/cyan]
[dim]Doctrine: Benni Master OS v9.4 (Skill 63 Cyber Sentinel OS) • Benni OS Core Engineering Group[/dim]"""
    console.print(Panel(banner, box=box.ROUNDED, border_style="yellow"))


@click.group()
def cli() -> None:
    """Agent Cyber Sentinel CLI - Runtime Defense for Autonomous AI Agents."""
    pass


@cli.command()
def info() -> None:
    """Display system metadata, doctrine, and POD-9 layers."""
    print_banner()
    table = Table(title="POD-9 Proof-of-Defense Architecture", box=box.SIMPLE_HEAVY)
    table.add_column("Layer", style="bold yellow")
    table.add_column("Domain", style="cyan")
    table.add_column("Gate", style="magenta")
    table.add_column("Runtime Defense Focus")

    table.add_row("L1", "Surface & Inventory", "SG-1", "Dynamic agent tool inventory and capability probing")
    table.add_row("L2", "Identity & Authority", "SG-2", "Principle of least privilege and authority locks")
    table.add_row("L3", "Supply Chain", "SG-3", "Package provenance and digest verification")
    table.add_row("L4", "Code & Configuration", "SG-4", "Tool call sanitization, SSRF protection, AST inspection")
    table.add_row("L5", "Agentic AI", "SG-5", "Prompt injection firewall, jailbreak & role hijack detection")
    table.add_row("L6", "Data & Cryptography", "SG-6", "Zero-leak secret interceptor and Shannon entropy redaction")
    table.add_row("L7", "Detection & Intel", "SG-7", "Real-time tamper alerts and evidence stream logging")
    table.add_row("L8", "Response & Recovery", "SG-8", "Automated step isolation and rollback compensation")
    table.add_row("L9", "Resilience & Continuity", "SG-9", "State recovery and durable ledger rehydration")

    console.print(table)


@cli.command("scan-text")
@click.argument("text")
@click.option("--strict/--no-strict", default=False, help="Fail with non-zero exit code on threats.")
def scan_text(text: str, strict: bool) -> None:
    """Scan a prompt or output text for prompt injection and secret leakage."""
    print_banner()
    sentinel = CyberSentinel(strict=False)
    result = sentinel.inspect_prompt(text)

    status_color = "green" if result.is_safe else "red"
    console.print(f"Safety Verdict: [{status_color}]{'SAFE' if result.is_safe else 'THREAT DETECTED'}[/{status_color}] | Threat Level: [bold]{result.threat_level.value.upper()}[/bold]")
    console.print(f"Evidence Digest: [dim]{result.evidence_digest}[/dim]\n")

    if result.findings:
        table = Table(title="Threat Findings", box=box.ROUNDED)
        table.add_column("Category", style="yellow")
        table.add_column("Rule", style="bold cyan")
        table.add_column("Confidence", style="magenta")
        table.add_column("Description")
        table.add_column("Action", style="red")

        for f in result.findings:
            table.add_row(
                f.category.value,
                f.rule_name,
                f"{f.confidence:.2f}",
                f.description,
                f.action.value.upper(),
            )
        console.print(table)
    else:
        console.print("[green][OK] No injection patterns or leaked credentials detected.[/green]")

    if result.sanitized_text != text:
        console.print(Panel(result.sanitized_text, title="Sanitized Output", border_style="cyan"))

    if strict and not result.is_safe:
        raise click.Abort()


@cli.command("scan-tool")
@click.argument("tool_name")
@click.argument("arguments_json")
def scan_tool(tool_name: str, arguments_json: str) -> None:
    """Scan a tool call invocation and arguments for SSRF and toxic execution."""
    print_banner()
    sentinel = CyberSentinel(strict=False)
    try:
        args = json.loads(arguments_json)
    except Exception as e:
        console.print(f"[red]Error parsing arguments JSON: {e}[/red]")
        raise click.Abort()

    result = sentinel.inspect_tool_call(tool_name, args)
    status_color = "green" if result.is_safe else "red"
    console.print(f"Tool Verdict: [{status_color}]{'PERMITTED' if result.is_safe else 'BLOCKED'}[/{status_color}] | Threat Level: [bold]{result.threat_level.value.upper()}[/bold]")

    if result.findings:
        table = Table(title="Tool Security Findings", box=box.ROUNDED)
        table.add_column("Category", style="yellow")
        table.add_column("Rule", style="bold cyan")
        table.add_column("Description")
        for f in result.findings:
            table.add_row(f.category.value, f.rule_name, f.description)
        console.print(table)
    else:
        console.print(f"[green][OK] Tool call '{tool_name}' meets safety standards.[/green]")


@cli.command("redact")
@click.argument("text")
def redact(text: str) -> None:
    """Redact API keys, private keys, and high-entropy credentials from text."""
    sentinel = CyberSentinel(strict=False)
    result = sentinel.inspect_output(text)
    console.print(result.sanitized_text)


@cli.command("verify-envelope")
@click.argument("envelope_file", type=click.Path(exists=True))
def verify_envelope(envelope_file: str) -> None:
    """Verify cryptographic signature of a POD-9 Proof-of-Defense envelope JSON file."""
    print_banner()
    with open(envelope_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    envelope = Pod9ProofEnvelope(**data)
    valid = envelope.verify()
    if valid:
        console.print(f"[bold green][OK] Envelope '{envelope.envelope_id}' is cryptographically VALID.[/bold green]")
        console.print(f"Layer: [cyan]{envelope.pod9_layer}[/cyan] | Gate: [cyan]{envelope.gate}[/cyan] | Decision: [bold]{envelope.decision}[/bold]")
    else:
        console.print(f"[bold red][FAIL] Envelope '{envelope.envelope_id}' has been TAMPERED WITH or is INVALID.[/bold red]")
        raise click.Abort()


if __name__ == "__main__":
    cli()
