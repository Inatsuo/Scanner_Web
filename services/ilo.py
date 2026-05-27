import logging
import re
import time

from .base import Service


class ILOService(Service):
    name = "iLO"
    creds_filename = "ilo.creds.json"
    patterns = re.compile(
        r"iLOGlobal|iLO\.js|/json/session_info|/sse/flash|Integrated Lights-Out",
        re.IGNORECASE,
    )
    config_path = "/json/login_session"

    def try_login(self, base_url, session):
        creds = self._load_creds()
        login_url = base_url.rstrip("/") + self.config_path

        for cred in creds[:self.max_creds]:
            payload = {
                "method":     "login",
                "user_login": cred["username"],
                "password":   cred["password"],
            }
            logging.info("  [%s] Trying %s on %s", self.name, cred["username"], login_url)
            try:
                r = session.post(login_url, json=payload, timeout=self.timeout,
                                 verify=False, allow_redirects=True)
            except Exception as e:
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
