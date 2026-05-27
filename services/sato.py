import logging
import re
import time

from .base import Service


class SATOService(Service):
    name = "SATO"
    creds_filename = "sato.creds.json"
    patterns = re.compile(
        r"SATO|CL4NX|CL6NX|CT4-LX|FX3-LX|sato_logo",
        re.IGNORECASE,
    )
    config_path = "/WebConfig/"

    _AUTH_PATH = "/WebConfig/lua/auth.lua"

    def try_login(self, base_url, session):
        creds = self._load_creds()
        base = base_url.rstrip("/")
        web_url  = base + self.config_path
        auth_url = base + self._AUTH_PATH

        # Mimic browser flow: prime the session by visiting /WebConfig/, then set cookie
        self._fetch(web_url, session)
        session.cookies.set("web", "true")

        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type":     "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin":           base,
            "Referer":          web_url,
            "Accept":           "*/*",
        }

        for cred in creds[:self.max_creds]:
            group = cred["username"]   # SATO calls this field "group"
            pwd   = cred["password"]
            payload = {"pw": pwd, "group": group}
            logging.info("  [%s] Trying group=%s pw=%s on %s",
                         self.name, group, pwd or "<empty>", auth_url)

            try:
                r = session.post(auth_url, data=payload, headers=headers,
                                 timeout=self.timeout, verify=False, allow_redirects=False)
            except Exception as e:
                logging.debug("  POST failed: %s", e)
                time.sleep(2)
                continue

            body_lower = r.text.lower()
            looks_failed = any(k in body_lower for k in ("error", "fail", "invalid", "denied", "incorrect"))
            if r.status_code == 200 and not looks_failed:
                return True, group, pwd
            time.sleep(2)

        return False, None, None
