import argparse
import ipaddress
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich import box
from rich.console import Console
from rich.table import Table

from scanner import scan

console = Console()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Lightweight SATO printer tester")
    p.add_argument("targets",      help="Text file — one IP / CIDR / range per line")
    p.add_argument("--check-auth", action="store_true", help="Try credentials from data/creds.json")
    p.add_argument("--workers",    type=int, default=30, help="Parallel scan workers (default: 30)")
    p.add_argument("--only-found", action="store_true", help="Show only detected targets in the table")
    p.add_argument("--verbose",    action="store_true", help="Show DEBUG logs (use --workers 1 for readable output)")
    return p.parse_args()


def _expand_targets(spec: str) -> list[str]:
    """Expand 'a.b.c.d' | 'a.b.c.d/N' | 'a.b.c.d-e' | 'a.b.c.d-a.b.c.e' into a list of IPs."""
    spec = spec.strip()
    if not spec:
        return []

    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
            hosts = [str(ip) for ip in net.hosts()]
            return hosts or [str(net.network_address)]
        except ValueError:
            console.print(f"[yellow]Invalid CIDR: {spec}[/yellow]")
            return []

    if "-" in spec:
        try:
            start_str, end_str = (s.strip() for s in spec.split("-", 1))
            start = ipaddress.IPv4Address(start_str)
            if "." not in end_str:
                base = ".".join(start_str.split(".")[:-1])
                end_str = f"{base}.{end_str}"
            end = ipaddress.IPv4Address(end_str)
            if int(end) < int(start):
                start, end = end, start
            return [str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1)]
        except ValueError:
            console.print(f"[yellow]Invalid range: {spec}[/yellow]")
            return []

    try:
        ipaddress.IPv4Address(spec)
        return [spec]
    except ValueError:
        console.print(f"[yellow]Invalid IP: {spec}[/yellow]")
        return []


def load_targets(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        console.print(f"[red]File not found: {path}[/red]")
        sys.exit(1)

    seen, targets = set(), []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for ip in _expand_targets(line):
            if ip not in seen:
                seen.add(ip)
                targets.append(ip)
    return targets


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s  %(message)s",
    )

    targets = load_targets(args.targets)
    if not targets:
        console.print("[red]No valid targets.[/red]")
        sys.exit(1)

    workers = max(1, min(args.workers, len(targets)))
    console.print(f"[bold]{len(targets)} target(s) loaded.[/bold] Scanning with {workers} worker(s)...\n")

    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan, ip, args.check_auth): ip for ip in targets}
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            marker = "[green]HIT[/green]" if r.is_target else "[dim]--[/dim]"
            console.print(f"  [{len(results):>3}/{len(targets)}] {marker} [cyan]{r.ip}[/cyan]")

    results.sort(key=lambda r: ipaddress.IPv4Address(r.ip))
    visible = [r for r in results if r.is_target] if args.only_found else results

    table = Table(title="SATO Scan Results", box=box.ROUNDED, show_lines=True, highlight=True)
    table.add_column("IP",    style="cyan", no_wrap=True)
    table.add_column("URL",   style="blue", no_wrap=True)
    table.add_column("SATO?", justify="center")
    table.add_column("Auth",  justify="center")

    for r in visible:
        col = "[green]YES[/green]" if r.is_target else "[dim]no[/dim]"

        if r.error:
            auth_col = f"[red]{r.error}[/red]"
        elif not r.is_target:
            auth_col = "[dim]—[/dim]"
        elif not args.check_auth:
            auth_col = "[dim]skipped[/dim]"
        elif r.winner:
            pwd_display = r.winner[1] if r.winner[1] else "<empty>"
            auth_col = f"[bold red]SUCCESS[/bold red] ({r.winner[0]}:{pwd_display})"
        else:
            auth_col = "[yellow]failed[/yellow]"

        table.add_row(r.ip, r.url or "—", col, auth_col)

    console.print()
    console.print(table)


if __name__ == "__main__":
    main()
