import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from scanner.process import scan_processes
from scanner.startup import check_startup
from scanner.network import scan_network
from scanner.file import monitor_files
from core.detector import calculate_threat_score, get_risk_level

console = Console()


# ─────────────────────────
# BANNER
# ─────────────────────────
def render_banner():
    banner = Text()
    banner.append("Threatify", style="bold cyan")
    banner.append("  |  Behavioral Threat Detection System\n", style="white")
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
        table.add_row(a["process"], str(a["pid"]), str(a["cpu"]), a["reason"])

    console.print(table)


def render_startup_table(alerts):
    table = Table(title="Startup Analysis")
    table.add_column("Name", style="cyan")
    table.add_column("Location", style="blue")
    table.add_column("Reason", style="red")

    for a in alerts:
        table.add_row(a["name"], a["location"], a["reason"])

    console.print(table)


def render_network_table(alerts):
    table = Table(title="Network Analysis")
    table.add_column("Process", style="cyan")
    table.add_column("PID", style="yellow")
    table.add_column("Remote", style="magenta")
    table.add_column("Status", style="blue")
    table.add_column("Reason", style="red")

    for a in alerts:
        table.add_row(a["process"], str(a["pid"]), a["remote"], a["status"],
                      a["reason"])

    console.print(table)


def render_file_table(alerts):
    table = Table(title="File Activity Analysis")
    table.add_column("File", style="yellow")
    table.add_column("Writes", style="cyan")
    table.add_column("Reason", style="red")

    for a in alerts:
        table.add_row(a["file"], str(a["writes"]), a["reason"])

    console.print(table)


def render_summary(score, risk):
    console.print("\n[bold]Threat Assessment[/bold]")
    console.print(f"Score: [cyan]{score}/100[/cyan]")

    color = {
        "SAFE": "green",
        "MEDIUM": "yellow",
        "HIGH": "red",
        "CRITICAL": "bold red"
    }[risk]

    console.print(f"Status: [{color}]{risk}[/{color}]")


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


def render_clean(message):
    console.print(f"[green]{message}[/green]")


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

    console.print("[bold]Starting system scan...[/bold]\n")

    process_alerts = scan_processes()
    startup_alerts = check_startup()
    network_alerts = scan_network()
    file_alerts = []

    if files:
        console.print("Monitoring file activity...")
        file_alerts = monitor_files(duration=5)

    # Process
    if process_alerts:
        render_process_table(process_alerts)
    else:
        render_clean("No suspicious processes detected")

    # Startup
    if startup_alerts:
        render_startup_table(startup_alerts)
    else:
        render_clean("No suspicious startup entries detected")

    # Network
    if network_alerts:
        render_network_table(network_alerts)
    else:
        render_clean("No suspicious network activity detected")

    # File
    if files:
        if file_alerts:
            render_file_table(file_alerts)
        else:
            render_clean("No suspicious file activity detected")

    # Detection Engine
    score = calculate_threat_score(process_alerts, startup_alerts,
                                   network_alerts, file_alerts)

    risk = get_risk_level(score)

    render_summary(score, risk)


# ─────────────────────────
# INDIVIDUAL COMMANDS
# ─────────────────────────
@main.command()
def processes():
    render_banner()
    alerts = scan_processes()

    if not alerts:
        render_clean("No suspicious processes detected")
        return

    render_process_table(alerts)


@main.command()
def startup():
    render_banner()
    alerts = check_startup()

    if not alerts:
        render_clean("No suspicious startup entries detected")
        return

    render_startup_table(alerts)


@main.command()
def network():
    render_banner()
    alerts = scan_network()

    if not alerts:
        render_clean("No suspicious network activity detected")
        return

    render_network_table(alerts)


@main.command()
@click.option("--time", default=10, help="Monitoring duration in seconds")
def files(time):
    render_banner()
    console.print(f"Monitoring file activity for {time} seconds...\n")

    alerts = monitor_files(duration=time)

    if not alerts:
        render_clean("No suspicious file activity detected")
        return

    render_file_table(alerts)


if __name__ == "__main__":
    main()
