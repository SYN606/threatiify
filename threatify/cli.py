import click
from rich import print
from rich.panel import Panel

from threatify.scanner.process import scan_processes


@click.group()
def main():
    """Threatify - System Threat Detection CLI"""
    pass


@main.command()
def scan():
    """Run full system scan"""
    print(Panel.fit("[bold cyan]Threatify Scan Started[/bold cyan]"))

    process_alerts = scan_processes()

    if not process_alerts:
        print("[green]✔ No suspicious processes found[/green]")
    else:
        print("[red]⚠ Suspicious processes detected:[/red]")
        for alert in process_alerts:
            print(f"[yellow]- {alert}[/yellow]")


@main.command()
def processes():
    """Scan only processes"""
    alerts = scan_processes()

    if not alerts:
        print("[green]✔ Clean[/green]")
    else:
        for alert in alerts:
            print(f"[red]{alert}[/red]")


if __name__ == "__main__":
    main()