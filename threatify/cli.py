import click
import subprocess
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from scanner.process import scan_processes
from scanner.startup import check_startup
from scanner.network import scan_network
from scanner.file import monitor_files

from core.detector import calculate_threat_score, get_risk_level
from core.aggregator import aggregate_by_process

console = Console()


# ─────────────────────────
# BANNER
# ─────────────────────────
def render_banner():
    banner = Text()
    banner.append("Threatify", style="bold cyan")
    banner.append("  |  Behavioral Threat Detection System\n")
    banner.append("Version 0.2.0\n", style="dim")

    console.print(Panel.fit(banner))


# ─────────────────────────
# HELPERS
# ─────────────────────────
def render_process_table(alerts):
    table = Table(title="Process Analysis")
    table.add_column("Process")
    table.add_column("PID")
    table.add_column("CPU (%)")
    table.add_column("Reason")

    for a in alerts:
        data = a.get("data", {})

        table.add_row(
            str(data.get("process", "unknown")),
            str(data.get("pid", "N/A")),
            str(data.get("cpu", "0")),
            a.get("reason", "N/A"),
        )

    console.print(table)


def render_startup_table(alerts):
    table = Table(title="Startup Analysis")
    table.add_column("Name")
    table.add_column("Location")
    table.add_column("Reason")

    for a in alerts:
        data = a.get("data", {})

        table.add_row(
            data.get("name", "unknown"),
            data.get("location", "unknown"),
            a.get("reason", "N/A"),
        )

    console.print(table)


def render_network_table(alerts):
    table = Table(title="Network Analysis")
    table.add_column("Process")
    table.add_column("PID")
    table.add_column("Remote")
    table.add_column("Reason")

    for a in alerts:
        data = a.get("data", {})

        table.add_row(
            str(data.get("process", "unknown")),
            str(data.get("pid", "N/A")),
            str(data.get("remote", "N/A")),
            a.get("reason", "N/A"),
        )

    console.print(table)


def render_file_table(alerts):
    table = Table(title="File Activity Analysis")
    table.add_column("File")
    table.add_column("Writes")
    table.add_column("Reason")

    for a in alerts:
        data = a.get("data", {})

        table.add_row(
            data.get("file", "unknown"),
            str(data.get("writes", 0)),
            a.get("reason", "N/A"),
        )

    console.print(table)


# ─────────────────────────
# PROCESS SUMMARY (KEY)
# ─────────────────────────
def render_process_summary(process_map):
    table = Table(title="Per-Process Threat Summary")

    table.add_column("PID")
    table.add_column("Process")
    table.add_column("Risk")
    table.add_column("Score")
    table.add_column("Alerts")

    # Sort by score descending
    sorted_items = sorted(
        process_map.items(),
        key=lambda x: x[1]["score"],
        reverse=True
    )

    for pid, info in sorted_items:
        process_name = "unknown"

        for a in info["alerts"]:
            data = a.get("data", {})
            if "process" in data:
                process_name = data["process"]
                break

        table.add_row(
            str(pid),
            process_name,
            info["risk"],
            str(info["score"]),
            str(len(info["alerts"]))
        )

    console.print(table)


def render_summary(score, risk):
    console.print("\nThreat Assessment")
    console.print(f"Score: {score}/100")
    console.print(f"Status: {risk}")


def render_clean(message):
    console.print(message)


# ─────────────────────────
# CLI ROOT
# ─────────────────────────
@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True)
@click.pass_context
def main(ctx, version):
    if version:
        console.print("Threatify v0.2.0")
        return

    if ctx.invoked_subcommand is None:
        console.print("Use --help for commands")


# ─────────────────────────
# FULL SCAN
# ─────────────────────────
@main.command()
@click.option("--files", is_flag=True)
def scan(files):
    render_banner()

    console.print("Starting system scan...\n")

    process_alerts = scan_processes()
    startup_alerts = check_startup()
    network_alerts = scan_network()
    file_alerts = []

    if files:
        console.print("Monitoring file activity...")
        file_alerts = monitor_files(duration=5)

    # ───── Tables ─────
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

    # ───── Aggregation ─────
    process_map = aggregate_by_process(
        process_alerts,
        startup_alerts,
        network_alerts,
        file_alerts,
    )

    if process_map:
        render_process_summary(process_map)

    # ───── Global Score ─────
    score = calculate_threat_score(
        process_alerts,
        startup_alerts,
        network_alerts,
        file_alerts,
    )

    risk = get_risk_level(score)

    render_summary(score, risk)


# ─────────────────────────
# MODULE COMMANDS
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
@click.option("--time", default=10)
def files(time):
    render_banner()
    console.print(f"Monitoring file activity for {time} seconds...\n")

    alerts = monitor_files(duration=time)

    if not alerts:
        render_clean("No suspicious file activity detected")
        return

    render_file_table(alerts)


# ─────────────────────────
# WEB COMMAND
# ─────────────────────────
@main.command()
def web():
    render_banner()
    console.print("Launching web dashboard...\n")

    try:
        subprocess.run(
            [sys.executable, "-m", "streamlit", "run", "threatify/webapp.py"],
            check=True
        )
    except FileNotFoundError:
        console.print("Streamlit not installed.")
    except Exception as e:
        console.print(f"Error: {e}")


# ─────────────────────────
# ENTRYPOINT
# ─────────────────────────
if __name__ == "__main__":
    main()