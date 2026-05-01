#!/usr/bin/env python3
"""
OPENLENS - Automated Open Source Intelligence Gathering Tool
Devloped By Aakarshit Bargotra & Kanav Samotra
Usage: python main.py -t example.com [options]
"""

import argparse
import sys
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from modules.subdomain import SubdomainEnumerator
from modules.dns_whois import DNSWhoisScanner
from modules.email_harvest import EmailHarvester
from modules.shodan_scan import ShodanScanner
from modules.google_dorks import GoogleDorker
from modules.breach_check import BreachChecker
from modules.dir_buster import DirBuster
from modules.js_scanner import JSScanner
from modules.report_gen import ReportGenerator
from config import Config

console = Console()

BANNER = """
[bold green]
 ██████╗ ██████╗ ███████╗███╗   ██╗██╗     ███████╗███╗   ██╗███████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║██║     ██╔════╝████╗  ██║██╔════╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║██║     █████╗  ██╔██╗ ██║███████╗
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║██║     ██╔══╝  ██║╚██╗██║╚════██║
╚██████╔╝██║     ███████╗██║ ╚████║███████╗███████╗██║ ╚████║███████║
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
[/bold green]
[dim]By Aakarshit Bargotra And Kanav Samotra[/dim]
[dim][/dim]
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Automated OSINT Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("--dns", action="store_true", help="Run DNS/WHOIS scan")
    parser.add_argument("--emails", action="store_true", help="Run email harvesting")
    parser.add_argument("--shodan", action="store_true", help="Run Shodan scan (requires API key)")
    parser.add_argument("--dorks", action="store_true", help="Run Google Dork queries")
    parser.add_argument("--breach", action="store_true", help="Check emails for breaches (requires API key)")
    parser.add_argument("--dirb", action="store_true", help="Run directory busting")
    parser.add_argument("--jscan", action="store_true", help="Download JS files and extract API endpoints")
    parser.add_argument("--all", action="store_true", help="Run all modules")
    parser.add_argument("--output", choices=["html", "json", "all"], default="html",
                        help="Report output format (default: html)")
    parser.add_argument("--output-dir", default="reports", help="Directory to save reports")
    return parser.parse_args()


def run_module(name, func, results_dict, key):
    """Run a module with spinner and error handling."""
    with Progress(
        SpinnerColumn(),
        TextColumn(f"[bold cyan]Running {name}...[/bold cyan]"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("", total=None)
        try:
            result = func()
            results_dict[key] = result
            count = len(result) if isinstance(result, (list, dict)) else "✓"
            console.print(f"[bold green]✓[/bold green] {name} completed — [yellow]{count}[/yellow] results")
        except Exception as e:
            results_dict[key] = []
            console.print(f"[bold red]✗[/bold red] {name} failed: [dim]{str(e)}[/dim]")


def print_summary(results: dict, target: str):
    console.print()
    table = Table(
        title=f"[bold]OSINT Summary — {target}[/bold]",
        show_header=True,
        header_style="bold magenta",
        border_style="dim"
    )
    table.add_column("Module", style="cyan", width=28)
    table.add_column("Findings", justify="right", style="yellow")
    table.add_column("Status", justify="center")

    module_map = {
        "subdomains": "Subdomains",
        "dns": "DNS Records",
        "emails": "Emails Found",
        "shodan": "Open Ports/Services",
        "dorks": "Dork Results (hits)",
        "breach": "Breached Accounts",
        "dirb": "Directory Hits",
        "jscan": "JS Files / API Endpoints",
    }

    for key, label in module_map.items():
        if key in results:
            data = results[key]
            if key == "dns" and isinstance(data, dict):
                count = len(data.get("records", []))
                status = "[green]Done[/green]" if count else "[dim]No results[/dim]"
                table.add_row(label, str(count), status)
                continue
            if key == "dorks":
                count = sum(1 for d in data if d.get("has_results") is True)
                status = f"[green]{count} confirmed hits[/green]" if count else "[dim]No confirmed hits[/dim]"
            elif key == "jscan" and isinstance(data, dict):
                js_count = len(data.get("js_files", []))
                ep_count = len(data.get("api_endpoints", []))
                count = f"{js_count} JS / {ep_count} endpoints"
                status = "[green]Done[/green]" if js_count else "[dim]No JS found[/dim]"
            else:
                count = len(data) if isinstance(data, (list, dict)) else "N/A"
                status = "[green]Done[/green]" if data else "[dim]No results[/dim]"
            table.add_row(label, str(count), status)
        else:
            table.add_row(label, "-", "[dim]Skipped[/dim]")

    console.print(table)


def main():
    console.print(BANNER)

    args = parse_args()
    target = args.target.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")

    console.print(Panel(
        f"[bold white]Target:[/bold white] [green]{target}[/green]\n"
        f"[bold white]Started:[/bold white] [dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n"
        f"[bold white]Output:[/bold white] [dim]{args.output}[/dim]",
        title="[bold yellow]⚡ Scan Configuration[/bold yellow]",
        border_style="yellow"
    ))

    config = Config()
    results = {}
    run_all = args.all

    if run_all or args.dns:
        scanner = DNSWhoisScanner(target)
        run_module("DNS & WHOIS", scanner.run, results, "dns")

    if run_all or args.subdomains:
        enumerator = SubdomainEnumerator(target)
        run_module("Subdomain Enumeration", enumerator.run, results, "subdomains")

    if run_all or args.emails:
        harvester = EmailHarvester(target)
        run_module("Email Harvesting", harvester.run, results, "emails")

    if run_all or args.shodan:
        if config.SHODAN_API_KEY:
            shodan = ShodanScanner(target, config.SHODAN_API_KEY)
            run_module("Shodan Scan", shodan.run, results, "shodan")
        else:
            console.print("[yellow]⚠[/yellow]  Shodan skipped — no API key in config.py")

    if run_all or args.dorks:
        dorker = GoogleDorker(target)
        run_module("Google Dorks", dorker.run, results, "dorks")

    if run_all or args.breach:
        if config.HIBP_API_KEY and results.get("emails"):
            checker = BreachChecker(results["emails"], config.HIBP_API_KEY)
            run_module("Breach Check", checker.run, results, "breach")
        else:
            console.print("[yellow]⚠[/yellow]  Breach check skipped — no API key or no emails found")

    if run_all or args.dirb:
        run_module("Directory Busting", DirBuster(target).run, results, "dirb")

    if run_all or args.jscan:
        run_module("JS Scanner", JSScanner(target).run, results, "jscan")

    print_summary(results, target)

    # Generate report
    console.print()
    console.print("[bold cyan]Generating report...[/bold cyan]")
    reporter = ReportGenerator(target, results, args.output_dir)

    if args.output == "all":
        reporter.generate_html()
        reporter.generate_json()
        console.print(f"[bold green]✓[/bold green] Reports saved to [yellow]{args.output_dir}/[/yellow]")
    elif args.output == "html":
        path = reporter.generate_html()
        console.print(f"[bold green]✓[/bold green] HTML report saved: [yellow]{path}[/yellow]")
    elif args.output == "json":
        path = reporter.generate_json()
        console.print(f"[bold green]✓[/bold green] JSON report saved: [yellow]{path}[/yellow]")

    console.print()
    console.print(Panel(
        "[bold green]Scan complete![/bold green] Remember to use this tool only on targets you have explicit permission to test.",
        border_style="green"
    ))


if __name__ == "__main__":
    main()
