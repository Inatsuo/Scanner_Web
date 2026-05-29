import logging
import re
import time

from .base import Service


class ZebraService(Service):
    name = "Zebra"
    creds_filename = "zebra.creds.json"
    patterns = re.compile(
        r"Zebra Technologies|ZebraNet|ZTC Z[A-Z]\d|zebra\.com|ZBR\d{6,}",
        re.IGNORECASE,
    )
    config_path = "/settings"
    max_creds   = 3

    # ACTION="authorize" is relative; with current URL "/settings" (no trailing
    # slash), HTML URL resolution gives "/authorize" at site root.
    _AUTH_PATH = "/authorize"

    # If the response still contains the login form, auth failed.
    _LOGIN_MARKERS = re.compile(
        r'type="password"|Autorisation|ENTER USERNAME|MOT DE PASSE',
        re.IGNORECASE,
    )

    def try_login(self, base_url, session):
        creds = self._load_creds()
        base = base_url.rstrip("/")
        login_url = base + self.config_path
        auth_url  = base + self._AUTH_PATH

        # Prime the session by visiting /settings (some firmwares set cookies)
        self._fetch(login_url, session)

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin":       base,
            "Referer":      login_url,
        }

        for cred in creds[:self.max_creds]:
            user = cred["username"]
            pwd  = cred["password"]
            payload = {"0": user, "1": pwd}

            logging.info("  [%s] Trying %s:%s on %s",
                         self.name, user or "<empty>", pwd or "<empty>", auth_url)

            try:
                r = session.post(auth_url, data=payload, headers=headers,
                                 timeout=self.timeout, verify=False, allow_redirects=True)
            except Exception as e:
                logging.debug("  POST failed: %s", e)
                time.sleep(2)
                continue

            # Success: 2xx/3xx AND response no longer shows the login form
            if r.status_code < 400 and not self._LOGIN_MARKERS.search(r.text):
                return True, user, pwd

            time.sleep(2)

        return False, None, None
