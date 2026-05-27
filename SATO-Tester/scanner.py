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
_USER_AGENT  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
_CREDS_PATH  = os.path.join(os.path.dirname(__file__), "data", "creds.json")
_WEB_PATH    = "/WebConfig/"
_AUTH_PATH   = "/WebConfig/lua/auth.lua"
MAX_ATTEMPTS = 2

_SATO_PATTERNS = re.compile(
    r"SATO|CL4NX|CL6NX|CT4-LX|FX3-LX|WebConfig",
    re.IGNORECASE,
)


@dataclass
class ScanResult:
    ip:           str
    url:          str | None
    is_target:    bool
    auth_success: bool
    winner:       tuple | None  # (group, password)
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


def _looks_like_sato(response: requests.Response) -> bool:
    if _SATO_PATTERNS.search(response.text):
        return True
    headers_str = " ".join(f"{k}: {v}" for k, v in response.headers.items())
    return bool(_SATO_PATTERNS.search(headers_str))


def _try_login(base_url: str, session: requests.Session) -> tuple[bool, str | None, str | None]:
    try:
        with open(_CREDS_PATH, "r", encoding="utf-8") as f:
            creds = json.load(f)
    except Exception as e:
        logging.warning("Could not load creds.json: %s", e)
        return False, None, None

    base = base_url.rstrip("/")
    web_url  = base + _WEB_PATH
    auth_url = base + _AUTH_PATH

    # Mimic browser flow: visit /WebConfig/ to collect cookies, then set web=true
    _fetch(web_url, session)
    session.cookies.set("web", "true")

    headers = {
        "X-Requested-With":  "XMLHttpRequest",
        "Content-Type":      "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin":            base,
        "Referer":           web_url,
        "Accept":            "*/*",
    }

    for i, cred in enumerate(creds):
        if i >= MAX_ATTEMPTS:
            break

        group = cred["username"]
        pwd   = cred["password"]
        payload = {"pw": pwd, "group": group}

        logging.info("  Trying group=%s pw=%s on %s", group, pwd or "<empty>", auth_url)

        try:
            r = session.post(auth_url, data=payload, headers=headers,
                             timeout=_TIMEOUT, verify=False, allow_redirects=False)
        except requests.RequestException as e:
            logging.debug("  POST failed: %s", e)
            time.sleep(2)
            continue

        logging.debug("  HTTP %d | body: %s | cookies: %s",
                      r.status_code, r.text[:300], session.cookies.get_dict())

        body_lower = r.text.lower()
        looks_failed = any(k in body_lower for k in ("error", "fail", "invalid", "denied", "incorrect"))

        if r.status_code == 200 and not looks_failed:
            return True, group, pwd

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

    is_target = _looks_like_sato(response)

    # Fallback: probe /WebConfig/ directly in case the root response didn't carry the signature
    if not is_target:
        probe = _fetch(url.rstrip("/") + _WEB_PATH, session)
        if probe is not None and _looks_like_sato(probe):
            is_target = True

    logging.info("  [%s] SATO detected: %s", ip, is_target)

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
