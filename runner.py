from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

from services.base import ScanResult, Service


def run_scans(
    services:   list[Service],
    targets:    list[str],
    check_auth: bool = False,
    workers:    int  = 30,
    on_result:  Optional[Callable[[ScanResult], None]] = None,
) -> list[ScanResult]:
    """Run each service against each target in parallel."""
    jobs = [(svc, ip) for ip in targets for svc in services]
    if not jobs:
        return []

    workers = max(1, min(workers, len(jobs)))
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(svc.scan, ip, check_auth): (svc, ip) for svc, ip in jobs}
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            if on_result is not None:
                on_result(r)
    return results
