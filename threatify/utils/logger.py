import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from threatify.scanner.process import scan_processes
from threatify.scanner.startup import check_startup
from threatify.scanner.network import scan_network
from threatify.scanner.file import monitor_files
from threatify.core.detector import calculate_threat_score, get_risk_level

# FIX: import logger with typing
from threatify.utils.logger import logger as _logger
import logging

logger: logging.Logger = _logger  # <- fixes Pylance

console = Console()


# ─────────────────────────
# BANNER
# ─────────────────────────
def render_banner():
    banner = Text()
    banner.append("Threatify", style="bold cyan")
    banner.append("  |  Behavioral Threat Detection System\n")
    banner.append("Version 0.1.0\n", style="dim")

    console.print(Panel.fit(banner))


# ─────────────────────────
# HELPERS
# ─────────────────────────
def render_process_table(alerts):
    table = Table(title="Process Analysis")
    table.add_column("Process", style="cyan")
    table.add_column("PID", style="yellow")
    table.add_column("CPU (%)", style="magenta")
    table.add_column("Reason", style="red")

    for a in alerts:
        table.add_row(
            a.get("process", "unknown"),
            str(a.get("pid", "N/A")),
            str(a.get("cpu", "0")),
            a.get("reason", "N/A"),
        )

    console.print(table)


def render_startup_table(alerts):
    table = Table(title="Startup Analysis")
    table.add_column("Name", style="cyan")
    table.add_column("Location", style="blue")
    table.add_column("Reason", style="red")

    for a in alerts:
        table.add_row(
            a.get("name", "unknown"),
            a.get("location", "unknown"),
            a.get("reason", "N/A"),
        )

    console.print(table)


def render_network_table(alerts):
    table = Table(title="Network Analysis")
    table.add_column("Process", style="cyan")
    table.add_column("PID", style="yellow")
    table.add_column("Remote", style="magenta")
    table.add_column("Status", style="blue")
    table.add_column("Reason", style="red")

    for a in alerts:
        table.add_row(
            a.get("process", "unknown"),
            str(a.get("pid", "N/A")),
            a.get("remote", "N/A"),
            a.get("status", "N/A"),
            a.get("reason", "N/A"),
        )

    console.print(table)


def render_file_table(alerts):
    table = Table(title="File Activity Analysis")
    table.add_column("File", style="yellow")
    table.add_column("Writes", style="cyan")
    table.add_column("Reason", style="red")

    for a in alerts:
        table.add_row(
            a.get("file", "unknown"),
            str(a.get("writes", 0)),
            a.get("reason", "N/A"),
        )

    console.print(table)


def render_summary(score, risk):
    console.print("\n[bold]Threat Assessment[/bold]")
    console.print(f"Score: [cyan]{score}/100[/cyan]")

    color = {
        "SAFE": "green",
        "MEDIUM": "yellow",
        "HIGH": "red",
        "CRITICAL": "bold red",
    }.get(risk, "white")

    console.print(f"Status: [{color}]{risk}[/{color}]")


def render_clean(message):
    console.print(f"[green]{message}[/green]")


def show_help():
    render_banner()

    table = Table(title="Commands")
    table.add_column("Command", style="cyan")
    table.add_column("Description")

    table.add_row("scan", "Run full system scan")
    table.add_row("processes", "Analyze running processes")
    table.add_row("startup", "Analyze startup persistence")
    table.add_row("network", "Analyze network connections")
    table.add_row("files", "Monitor file activity")
    table.add_row("--version", "Show version information")

    console.print(table)

    console.print("\nExamples:")
    console.print("  threatify scan")
    console.print("  threatify scan --files")
    console.print("  threatify files --time 15")


# ─────────────────────────
# CLI ROOT
# ─────────────────────────
@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Show Threatify version")
@click.pass_context
def main(ctx, version):
    if version:
        console.print("Threatify v0.1.0")
        return

    if ctx.invoked_subcommand is None:
        show_help()


# ─────────────────────────
# FULL SCAN
# ─────────────────────────
@main.command()
@click.option("--files", is_flag=True, help="Include file monitoring")
def scan(files):
    render_banner()

    logger.info("Starting system scan")

    try:
        process_alerts = scan_processes()
        logger.info(f"Process scan completed ({len(process_alerts)} alerts)")

        startup_alerts = check_startup()
        logger.info(f"Startup scan completed ({len(startup_alerts)} alerts)")

        network_alerts = scan_network()
        logger.info(f"Network scan completed ({len(network_alerts)} alerts)")

        file_alerts = []

        if files:
            logger.info("Starting file monitoring")
            file_alerts = monitor_files(duration=5)
            logger.info(
                f"File monitoring completed ({len(file_alerts)} alerts)")

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        console.print("[red]Scan failed. Check logs.[/red]")
        return

    console.print()

    if process_alerts:
        render_process_table(process_alerts)
    else:
        render_clean("No suspicious processes detected")

    if startup_alerts:
        render_startup_table(startup_alerts)
    else:
        render_clean("No suspicious startup entries detected")

    if network_alerts:
        render_network_table(network_alerts)
    else:
        render_clean("No suspicious network activity detected")

    if files:
        if file_alerts:
            render_file_table(file_alerts)
        else:
            render_clean("No suspicious file activity detected")

    score = calculate_threat_score(
        process_alerts,
        startup_alerts,
        network_alerts,
        file_alerts,
    )

    risk = get_risk_level(score)

    logger.info(f"Threat score: {score}")
    logger.info(f"Risk level: {risk}")

    render_summary(score, risk)


# ─────────────────────────
# COMMANDS
# ─────────────────────────
@main.command()
def processes():
    render_banner()
    logger.info("Running process scan")

    alerts = scan_processes()

    if not alerts:
        render_clean("No suspicious processes detected")
        return

    render_process_table(alerts)


@main.command()
def startup():
    render_banner()
    logger.info("Running startup scan")

    alerts = check_startup()

    if not alerts:
        render_clean("No suspicious startup entries detected")
        return

    render_startup_table(alerts)


@main.command()
def network():
    render_banner()
    logger.info("Running network scan")

    alerts = scan_network()

    if not alerts:
        render_clean("No suspicious network activity detected")
        return

    render_network_table(alerts)


@main.command()
@click.option("--time", default=10, help="Monitoring duration in seconds")
def files(time):
    render_banner()
    logger.info(f"Monitoring file activity for {time} seconds")

    alerts = monitor_files(duration=time)

    if not alerts:
        render_clean("No suspicious file activity detected")
        return

    render_file_table(alerts)


if __name__ == "__main__":
    main()
