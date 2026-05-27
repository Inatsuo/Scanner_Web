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

_TIMEOUT    = 10
_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
_CREDS_PATH = os.path.join(os.path.dirname(__file__), "data", "creds.json")
MAX_ATTEMPTS = 2

_ILO_PATTERNS = re.compile(
    r"iLOGlobal|iLO\.js|/json/session_info|/sse/flash|Integrated Lights-Out",
    re.IGNORECASE,
)


@dataclass
class ScanResult:
    ip:           str
    url:          str | None
    is_ilo:       bool
    auth_success: bool
    winner:       tuple | None  # (username, password)
    error:        str | None


def _port_open(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=5):
            return True
    except OSError:
        return False


def _fetch(url: str, session: requests.Session) -> requests.Response | None:
    try:
        return session.get(url, timeout=_TIMEOUT, verify=False, allow_redirects=True)
    except requests.RequestException:
        return None


def _try_login(base_url: str, session: requests.Session) -> tuple[bool, str | None, str | None]:
    try:
        with open(_CREDS_PATH, "r", encoding="utf-8") as f:
            creds = json.load(f)
    except Exception as e:
        logging.warning("Could not load creds.json: %s", e)
        return False, None, None

    for i, cred in enumerate(creds):
        if i >= MAX_ATTEMPTS:
            break

        login_url = base_url.rstrip("/") + cred.get("path", "/json/login_session")
        payload = {
            cred.get("username_field", "user_login"): cred["username"],
            cred.get("password_field", "password"):   cred["password"],
            **cred.get("json_extra", {}),
        }

        logging.info("  Trying %s on %s", cred["username"], login_url)

        try:
            r = session.post(login_url, json=payload, timeout=_TIMEOUT, verify=False, allow_redirects=True)
            logging.debug("  HTTP %d | body: %s", r.status_code, r.text[:300])
        except requests.RequestException as e:
            logging.debug("  POST failed: %s", e)
            time.sleep(2)
            continue

        if r.status_code == 200:
            try:
                body = r.json()
                if {"session_key", "token", "access_token"} & set(body.keys()):
                    return True, cred["username"], cred["password"]
            except Exception:
                pass

        time.sleep(2)

    return False, None, None


def scan(ip: str, check_auth: bool = False) -> ScanResult:
    port_443 = _port_open(ip, 443)
    port_80  = _port_open(ip, 80)

    if not port_443 and not port_80:
        return ScanResult(ip=ip, url=None, is_ilo=False, auth_success=False, winner=None, error="no open web ports")

    url     = f"https://{ip}" if port_443 else f"http://{ip}"
    session = requests.Session()
    session.headers["User-Agent"] = _USER_AGENT

    response = _fetch(url, session)
    if response is None and url.startswith("https://") and port_80:
        url      = f"http://{ip}"
        response = _fetch(url, session)

    if response is None:
        return ScanResult(ip=ip, url=url, is_ilo=False, auth_success=False, winner=None, error="HTTP request failed")

    is_ilo = bool(_ILO_PATTERNS.search(response.text))
    logging.info("  [%s] iLO detected: %s", ip, is_ilo)

    if not is_ilo:
        return ScanResult(ip=ip, url=url, is_ilo=False, auth_success=False, winner=None, error=None)

    auth_success, u, p = False, None, None
    if check_auth:
        auth_success, u, p = _try_login(url, session)

    return ScanResult(
        ip=ip, url=url, is_ilo=True,
        auth_success=auth_success,
        winner=(u, p) if auth_success else None,
        error=None,
    )
