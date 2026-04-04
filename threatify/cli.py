import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from threatify.scanner.process import scan_processes
from threatify.scanner.startup import check_startup
from threatify.scanner.network import scan_network
from threatify.scanner.file import monitor_files
from threatify.core.detector import calculate_threat_score, get_risk_level

console = Console()


# ─────────────────────────
# HELPERS (Reusable UI)
# ─────────────────────────
def render_process_table(alerts):
    table = Table(title="⚠ Suspicious Processes")
    table.add_column("Process", style="cyan")
    table.add_column("PID", style="yellow")
    table.add_column("CPU%", style="magenta")
    table.add_column("Reason", style="red")

    for a in alerts:
        table.add_row(a["process"], str(a["pid"]), str(a["cpu"]), a["reason"])

    console.print(table)


def render_startup_table(alerts):
    table = Table(title="⚠ Startup Threats")
    table.add_column("Name", style="cyan")
    table.add_column("Location", style="blue")
    table.add_column("Reason", style="red")

    for a in alerts:
        table.add_row(a["name"], a["location"], a["reason"])

    console.print(table)


def render_network_table(alerts):
    table = Table(title="⚠ Network Threats")
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
    table = Table(title="⚠ File Activity Threats")
    table.add_column("File", style="yellow")
    table.add_column("Writes", style="cyan")
    table.add_column("Reason", style="red")

    for a in alerts:
        table.add_row(a["file"], str(a["writes"]), a["reason"])

    console.print(table)


def render_summary(score, risk):
    console.print("\n[bold]Threat Analysis[/bold]")
    console.print(f"Threat Score: [cyan]{score}/100[/cyan]")

    color = {
        "SAFE": "green",
        "MEDIUM": "yellow",
        "HIGH": "red",
        "CRITICAL": "bold red"
    }[risk]

    console.print(f"[{color}]System Status: {risk}[/{color}]")


def show_help():
    console.print(Panel.fit("[bold cyan]Threatify CLI[/bold cyan]"))

    table = Table(title="Available Commands")
    table.add_column("Command", style="cyan")
    table.add_column("Description", style="white")

    table.add_row("scan", "Run full system scan")
    table.add_row("processes", "Scan running processes")
    table.add_row("startup", "Scan startup programs")
    table.add_row("network", "Scan network connections")
    table.add_row("files", "Monitor file activity")
    table.add_row("--version", "Show version info")

    console.print(table)

    console.print("\n[bold]Examples:[/bold]")
    console.print("[yellow]threatify scan[/yellow]")
    console.print("[yellow]threatify files --time 15[/yellow]")


# ─────────────────────────
# CLI ROOT
# ─────────────────────────
@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Show Threatify version")
@click.pass_context
def main(ctx, version):
    """Threatify - Behavioral Threat Detection CLI"""

    if version:
        console.print("[cyan]Threatify v0.1.0[/cyan]")
        return

    if ctx.invoked_subcommand is None:
        show_help()


# ─────────────────────────
# FULL SYSTEM SCAN
# ─────────────────────────
@main.command()
@click.option("--files", is_flag=True, help="Include file monitoring")
def scan(files):
    """Run full system scan"""

    console.print(Panel.fit("[bold cyan]🚀 Threatify Full Scan[/bold cyan]"))

    process_alerts = scan_processes()
    startup_alerts = check_startup()
    network_alerts = scan_network()
    file_alerts = []

    if files:
        console.print("[cyan]Monitoring file activity (5s)...[/cyan]")
        file_alerts = monitor_files(duration=5)

    # ─── Process ───
    if process_alerts:
        render_process_table(process_alerts)
    else:
        console.print("[green]✔ No suspicious processes[/green]")

    # ─── Startup ───
    if startup_alerts:
        render_startup_table(startup_alerts)
    else:
        console.print("[green]✔ No suspicious startup entries[/green]")

    # ─── Network ───
    if network_alerts:
        render_network_table(network_alerts)
    else:
        console.print("[green]✔ No suspicious network activity[/green]")

    # ─── File ───
    if files:
        if file_alerts:
            render_file_table(file_alerts)
        else:
            console.print("[green]✔ No suspicious file activity[/green]")

    # ─── Detection Engine ───
    score = calculate_threat_score(process_alerts, startup_alerts,
                                   network_alerts, file_alerts)

    risk = get_risk_level(score)

    render_summary(score, risk)


# ─────────────────────────
# INDIVIDUAL COMMANDS
# ─────────────────────────
@main.command()
def processes():
    alerts = scan_processes()
    if not alerts:
        console.print("[green]✔ No suspicious processes[/green]")
        return
    render_process_table(alerts)


@main.command()
def startup():
    alerts = check_startup()
    if not alerts:
        console.print("[green]✔ No suspicious startup entries[/green]")
        return
    render_startup_table(alerts)


@main.command()
def network():
    alerts = scan_network()
    if not alerts:
        console.print("[green]✔ No suspicious network activity[/green]")
        return
    render_network_table(alerts)


@main.command()
@click.option("--time", default=10, help="Monitoring duration in seconds")
def files(time):
    console.print(f"[cyan]Monitoring file activity for {time}s...[/cyan]")

    alerts = monitor_files(duration=time)

    if not alerts:
        console.print("[green]✔ No suspicious file activity[/green]")
        return

    render_file_table(alerts)


if __name__ == "__main__":
    main()
