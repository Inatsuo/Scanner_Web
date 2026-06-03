import csv
import time
from datetime import datetime
from pathlib import Path

from rich import box
from rich.console import Console
from rich.table import Table

from services.base import ScanResult


class ScanReport:
    """Live scan stats + streaming hit log.

    Every detected target is appended to a CSV and the file is flushed
    immediately, so the log stays complete even if the scan is interrupted
    (Ctrl+C) partway through a long run. `record()` is called once per
    ScanResult from the main thread (see runner.run_scans), so no locking is
    needed.
    """

    FIELDS = ["timestamp", "ip", "service", "url", "detected",
              "auth", "username", "password", "error"]

    def __init__(self, out_path: Path, total: int, console: Console,
                 *, check_auth: bool, progress_every: int = 2000):
        self.out_path = out_path
        self.total = total
        self.console = console
        self.check_auth = check_auth
        self.progress_every = max(1, progress_every)
        self.start = time.monotonic()

        # counters
        self.scanned = 0
        self.hits = 0          # service detected
        self.auth_success = 0
        self.auth_failed = 0
        self.errors = 0
        self.clean = 0         # reachable, nothing detected, no error

        out_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(out_path, "w", encoding="utf-8", newline="")
        self._writer = csv.DictWriter(self._fh, fieldnames=self.FIELDS)
        self._writer.writeheader()
        self._fh.flush()

    # -- per-result ---------------------------------------------------------

    def record(self, r: ScanResult) -> None:
        self.scanned += 1

        if r.error:
            self.errors += 1
        elif r.detected:
            self.hits += 1
            if self.check_auth:
                if r.auth_success:
                    self.auth_success += 1
                else:
                    self.auth_failed += 1
        else:
            self.clean += 1

        if r.detected:
            self._write_hit(r)
            self._print_hit(r)

        if self.scanned % self.progress_every == 0:
            self._print_progress()

    def _auth_label(self, r: ScanResult) -> str:
        if not r.detected:
            return ""
        if not self.check_auth:
            return "skipped"
        return "SUCCESS" if r.auth_success else "failed"

    def _write_hit(self, r: ScanResult) -> None:
        user, pwd = "", ""
        if r.winner:
            user = r.winner[0] or ""
            pwd = r.winner[1] if r.winner[1] else ""
        self._writer.writerow({
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "ip": r.ip,
            "service": r.service,
            "url": r.url or "",
            "detected": "yes" if r.detected else "no",
            "auth": self._auth_label(r),
            "username": user,
            "password": pwd,
            "error": r.error or "",
        })
        self._fh.flush()

    def _print_hit(self, r: ScanResult) -> None:
        if r.winner:
            pwd = r.winner[1] if r.winner[1] else "<empty>"
            extra = f"  [bold red]AUTH {r.winner[0]}:{pwd}[/bold red]"
        elif self.check_auth:
            extra = "  [yellow]auth failed[/yellow]"
        else:
            extra = ""
        self.console.print(
            f"  [green]HIT[/green] [cyan]{r.ip:<15}[/cyan] "
            f"[magenta]{r.service}[/magenta] [blue]{r.url or ''}[/blue]{extra}"
        )

    def _print_progress(self) -> None:
        pct = (self.scanned / self.total * 100) if self.total else 0.0
        elapsed = time.monotonic() - self.start
        rate = self.scanned / elapsed if elapsed else 0.0
        self.console.print(
            f"[dim]  …{self.scanned}/{self.total} ({pct:4.1f}%)  "
            f"hits={self.hits} auth={self.auth_success} "
            f"errors={self.errors}  {rate:.0f}/s[/dim]"
        )

    # -- finalize -----------------------------------------------------------

    def close(self) -> None:
        try:
            self._fh.flush()
            self._fh.close()
        except Exception:
            pass

    def summary(self) -> Table:
        elapsed = time.monotonic() - self.start
        rate = self.scanned / elapsed if elapsed else 0.0

        t = Table(title="Scan Summary", box=box.ROUNDED, show_header=False,
                  title_style="bold")
        t.add_column("metric", style="bold")
        t.add_column("value", justify="right")

        t.add_row("Scanned", f"{self.scanned}/{self.total}")
        t.add_row("Hits (detected)", f"[green]{self.hits}[/green]")
        if self.check_auth:
            t.add_row("Auth success", f"[bold red]{self.auth_success}[/bold red]")
            t.add_row("Auth failed", f"[yellow]{self.auth_failed}[/yellow]")
        t.add_row("No detection", f"[dim]{self.clean}[/dim]")
        t.add_row("Errors / unreachable", f"[red]{self.errors}[/red]")
        t.add_row("Elapsed", f"{elapsed:.0f}s ({rate:.0f}/s)")
        t.add_row("Hits saved to", f"[blue]{self.out_path}[/blue]")
        return t
