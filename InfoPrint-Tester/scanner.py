import json
import logging
import os
import re
import socket
import time
from dataclasses import dataclass

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT     = 10
_USER_AGENT  = "curl/8.0.0"
_CREDS_PATH  = os.path.join(os.path.dirname(__file__), "data", "creds.json")
_CONFIG_PATH = "/indexConf.html"
MAX_ATTEMPTS = 2

_INFOPRINT_PATTERNS = re.compile(
    r"InfoPrint|Printronix|ptxLogo|LiquidStyles|6700|IPDS|Ricoh|Microplex|emHTTPD",
    re.IGNORECASE,
)


@dataclass
class ScanResult:
    ip:           str
    url:          str | None
    is_target:    bool
    auth_success: bool
    winner:       tuple | None  # (username, password)
    error:        str | None


def _port_open(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=5):
            return True
    except OSError:
        return False


def _fetch(url: str, session: requests.Session, auth=None) -> requests.Response | None:
    try:
        return session.get(url, timeout=_TIMEOUT, verify=False, allow_redirects=True, auth=auth)
    except requests.RequestException:
        return None


def _looks_like_infoprint(response: requests.Response) -> bool:
    if _INFOPRINT_PATTERNS.search(response.text):
        return True
    headers_str = " ".join(f"{k}: {v}" for k, v in response.headers.items())
    return bool(_INFOPRINT_PATTERNS.search(headers_str))


def _try_login(base_url: str, session: requests.Session) -> tuple[bool, str | None, str | None]:
    try:
        with open(_CREDS_PATH, "r", encoding="utf-8") as f:
            creds = json.load(f)
    except Exception as e:
        logging.warning("Could not load creds.json: %s", e)
        return False, None, None

    target_url = base_url.rstrip("/") + _CONFIG_PATH

    for i, cred in enumerate(creds):
        if i >= MAX_ATTEMPTS:
            break

        user = cred["username"]
        pwd  = cred["password"]
        logging.info("  Trying %s:%s on %s", user, pwd or "<empty>", target_url)

        r = _fetch(target_url, session, auth=(user, pwd))
        if r is None:
            time.sleep(2)
            continue

        logging.debug("  HTTP %d | body: %s", r.status_code, r.text[:300])

        if r.status_code == 200 and _looks_like_infoprint(r):
            return True, user, pwd

        time.sleep(2)

    return False, None, None


def scan(ip: str, check_auth: bool = False) -> ScanResult:
    port_443 = _port_open(ip, 443)
    port_80  = _port_open(ip, 80)

    if not port_443 and not port_80:
        return ScanResult(ip=ip, url=None, is_target=False, auth_success=False, winner=None, error="no open web ports")

    url     = f"https://{ip}" if port_443 else f"http://{ip}"
    session = requests.Session()
    session.headers["User-Agent"] = _USER_AGENT

    response = _fetch(url, session)
    if response is None and url.startswith("https://") and port_80:
        url      = f"http://{ip}"
        response = _fetch(url, session)

    if response is None:
        return ScanResult(ip=ip, url=url, is_target=False, auth_success=False, winner=None, error="HTTP request failed")

    logging.debug("  [%s] GET / body (%d bytes): %s", ip, len(response.text), response.text[:500])

    is_target = _looks_like_infoprint(response)

    # Fallback: probe the config path — its 401 challenge may identify the device
    if not is_target:
        probe = _fetch(url.rstrip("/") + _CONFIG_PATH, session)
        if probe is not None and _looks_like_infoprint(probe):
            is_target = True

    logging.info("  [%s] InfoPrint detected: %s", ip, is_target)

    if not is_target:
        return ScanResult(ip=ip, url=url, is_target=False, auth_success=False, winner=None, error=None)

    auth_success, u, p = False, None, None
    if check_auth:
        auth_success, u, p = _try_login(url, session)

    return ScanResult(
        ip=ip, url=url, is_target=True,
        auth_success=auth_success,
        winner=(u, p) if auth_success else None,
        error=None,
    )
