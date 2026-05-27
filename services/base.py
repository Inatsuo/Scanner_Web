import json
import logging
import re
import socket
from dataclasses import dataclass
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class ScanResult:
    ip:           str
    service:      str
    detected:     bool
    url:          str | None
    auth_success: bool
    winner:       tuple | None  # (username, password) on success
    error:        str | None


class Service:
    """Base class — subclass and override class attributes (and optionally try_login / detect)."""

    name: str = ""
    creds_filename: str = ""
    patterns: re.Pattern = re.compile("")
    config_path: str = "/"
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    ports: tuple = (443, 80)
    timeout: int = 10
    max_creds: int = 2

    def __init__(self, data_dir: Path):
        self.creds_path = data_dir / self.creds_filename

    # -- low-level helpers --------------------------------------------------

    def _port_open(self, ip: str, port: int) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=5):
                return True
        except OSError:
            return False

    def _fetch(self, url: str, session: requests.Session, **kw) -> requests.Response | None:
        try:
            return session.get(url, timeout=self.timeout, verify=False, allow_redirects=True, **kw)
        except requests.RequestException:
            return None

    def _matches(self, response: requests.Response | None) -> bool:
        if response is None:
            return False
        if self.patterns.search(response.text):
            return True
        headers_str = " ".join(f"{k}: {v}" for k, v in response.headers.items())
        return bool(self.patterns.search(headers_str))

    def _load_creds(self) -> list:
        try:
            with open(self.creds_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logging.warning("[%s] Could not load %s: %s", self.name, self.creds_path, e)
            return []

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.headers["User-Agent"] = self.user_agent
        return s

    # -- overridable steps --------------------------------------------------

    def detect(self, base_url: str, session: requests.Session) -> bool:
        """Default: regex match on root, fallback probe on config_path."""
        response = self._fetch(base_url, session)
        if self._matches(response):
            return True
        probe = self._fetch(base_url.rstrip("/") + self.config_path, session)
        return self._matches(probe)

    def try_login(self, base_url: str, session: requests.Session) -> tuple[bool, str | None, str | None]:
        """Default: HTTP Basic Auth against config_path, success if 200 + pattern match."""
        creds = self._load_creds()
        target_url = base_url.rstrip("/") + self.config_path
        for cred in creds[:self.max_creds]:
            user = cred["username"]
            pwd  = cred["password"]
            logging.info("  [%s] Trying %s:%s on %s", self.name, user, pwd or "<empty>", target_url)
            r = self._fetch(target_url, session, auth=(user, pwd))
            if r is not None and r.status_code == 200 and self._matches(r):
                return True, user, pwd
        return False, None, None

    # -- entry point --------------------------------------------------------

    def scan(self, ip: str, check_auth: bool = False) -> ScanResult:
        port_443 = 443 in self.ports and self._port_open(ip, 443)
        port_80  = 80  in self.ports and self._port_open(ip, 80)

        if not port_443 and not port_80:
            return ScanResult(ip=ip, service=self.name, detected=False, url=None,
                              auth_success=False, winner=None, error="no open web ports")

        session = self._make_session()
        url = f"https://{ip}" if port_443 else f"http://{ip}"
        probe = self._fetch(url, session)
        if probe is None and url.startswith("https://") and port_80:
            url = f"http://{ip}"
            probe = self._fetch(url, session)
        if probe is None:
            return ScanResult(ip=ip, service=self.name, detected=False, url=url,
                              auth_success=False, winner=None, error="HTTP request failed")

        try:
            detected = self.detect(url, session)
        except Exception as e:
            return ScanResult(ip=ip, service=self.name, detected=False, url=url,
                              auth_success=False, winner=None, error=f"detect error: {e}")

        if not detected:
            return ScanResult(ip=ip, service=self.name, detected=False, url=url,
                              auth_success=False, winner=None, error=None)

        auth_success, u, p = False, None, None
        if check_auth:
            try:
                auth_success, u, p = self.try_login(url, session)
            except Exception as e:
                return ScanResult(ip=ip, service=self.name, detected=True, url=url,
                                  auth_success=False, winner=None, error=f"auth error: {e}")

        return ScanResult(
            ip=ip, service=self.name, detected=True, url=url,
            auth_success=auth_success,
            winner=(u, p) if auth_success else None,
            error=None,
        )
