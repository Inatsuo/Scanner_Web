import argparse
import ipaddress
import logging
import sys
from datetime import datetime
from pathlib import Path

from rich import box
from rich.console import Console
from rich.table import Table

import targets as targets_mod
from report import ScanReport
from runner import run_scans
from services import ALL_SERVICES, SERVICES_BY_NAME

console = Console()


def parse_args() -> argparse.Namespace:
    available = ", ".join(s.name for s in ALL_SERVICES)
    p = argparse.ArgumentParser(description="Unified web service scanner")
    p.add_argument("targets",      help="Text file — one IP / CIDR / range per line")
    p.add_argument("--check-auth", action="store_true", help="Try default credentials when a service is detected")
    p.add_argument("--service",    default="", help=f"Comma-separated list of services (default: all). Options: {available}")
    p.add_argument("--workers",    type=int, default=30, help="Parallel scan workers (default: 30)")
    p.add_argument("--out",        default="", help="CSV file for hits (default: results/hits_<timestamp>.csv). Flushed per hit, so partial scans are kept.")
    p.add_argument("--only-found", action="store_true", help="Show only detected targets in the table")
    p.add_argument("--verbose",    action="store_true", help="Show DEBUG logs (pair with --workers 1 for readable output)")
    return p.parse_args()


def _pick_services(spec: str):
    if not spec:
        return ALL_SERVICES
    wanted = [name.strip().lower() for name in spec.split(",") if name.strip()]
    picked = []
    for name in wanted:
        if name not in SERVICES_BY_NAME:
            console.print(f"[red]Unknown service:[/red] {name}. Available: {', '.join(SERVICES_BY_NAME)}")
            sys.exit(1)
        picked.append(SERVICES_BY_NAME[name])
    return picked


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s  %(message)s",
    )

    targets = targets_mod.load(args.targets)
    if not targets:
        console.print(f"[red]No valid targets in {args.targets}.[/red]")
        sys.exit(1)

    service_classes = _pick_services(args.service)
    data_dir = Path(__file__).parent / "data"
    services = [cls(data_dir) for cls in service_classes]

    total = len(services) * len(targets)
    workers = max(1, min(args.workers, total))
    console.print(
        f"[bold]{len(targets)} target(s) × {len(services)} service(s) "
        f"= {total} scan(s)[/bold] with {workers} worker(s)...\n"
    )

    out_path = Path(args.out) if args.out else (
        Path("results") / f"hits_{datetime.now():%Y%m%d_%H%M%S}.csv"
    )
    report = ScanReport(out_path, total, console, check_auth=args.check_auth)

    results: list = []
    try:
        results = run_scans(services, targets, check_auth=args.check_auth,
                            workers=args.workers, on_result=report.record)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — partial hits already saved.[/yellow]")
    finally:
        report.close()

    console.print()
    console.print(report.summary())

    if not results:
        # Interrupted (or nothing scanned): the CSV holds whatever hits we got.
        return

    results.sort(key=lambda r: (ipaddress.IPv4Address(r.ip), r.service))
    visible = [r for r in results if r.detected] if args.only_found else results

    # Don't dump a million rows to the terminal — the CSV already has the hits.
    MAX_ROWS = 500
    truncated = max(0, len(visible) - MAX_ROWS)
    visible = visible[:MAX_ROWS]

    table = Table(title="Service Scan Results", box=box.ROUNDED, show_lines=True, highlight=True)
    table.add_column("IP",       style="cyan",    no_wrap=True)
    table.add_column("Service",  style="magenta", no_wrap=True)
    table.add_column("URL",      style="blue",    no_wrap=True)
    table.add_column("Detected", justify="center")
    table.add_column("Auth",     justify="center")

    for r in visible:
        det_col = "[green]YES[/green]" if r.detected else "[dim]no[/dim]"

        if r.error:
            auth_col = f"[red]{r.error}[/red]"
        elif not r.detected:
            auth_col = "[dim]—[/dim]"
        elif not args.check_auth:
            auth_col = "[dim]skipped[/dim]"
        elif r.winner:
            pwd_display = r.winner[1] if r.winner[1] else "<empty>"
            auth_col = f"[bold red]SUCCESS[/bold red] ({r.winner[0]}:{pwd_display})"
        else:
            auth_col = "[yellow]failed[/yellow]"

        table.add_row(r.ip, r.service, r.url or "—", det_col, auth_col)

    console.print()
    console.print(table)
    if truncated:
        console.print(
            f"[dim]… {truncated} more row(s) hidden. "
            f"Use --only-found, or open the CSV: {out_path}[/dim]"
        )


if __name__ == "__main__":
    main()
