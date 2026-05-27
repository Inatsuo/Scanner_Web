import ipaddress
import sys
from pathlib import Path


def expand(spec: str) -> list[str]:
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
            print(f"Warning: invalid CIDR {spec!r}", file=sys.stderr)
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
            print(f"Warning: invalid range {spec!r}", file=sys.stderr)
            return []

    try:
        ipaddress.IPv4Address(spec)
        return [spec]
    except ValueError:
        print(f"Warning: invalid IP {spec!r}", file=sys.stderr)
        return []


def load(path: str | Path) -> list[str]:
    """Read a targets file, expand every spec, dedupe."""
    p = Path(path)
    if not p.exists():
        return []
    seen, targets = set(), []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for ip in expand(line):
            if ip not in seen:
                seen.add(ip)
                targets.append(ip)
    return targets
