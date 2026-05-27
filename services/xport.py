import re

from .base import Service


class XPortService(Service):
    name = "XPort"
    creds_filename = "xport.creds.json"
    patterns = re.compile(
        r"Lantronix|XPort|sTargetURL",
        re.IGNORECASE,
    )
    config_path = "/secure/ltx_conf.htm"

    def detect(self, base_url, session):
        # Standard fingerprint first
        response = self._fetch(base_url, session)
        if self._matches(response):
            return True
        # Probe the XPort-specific config path
        probe = self._fetch(base_url.rstrip("/") + self.config_path, session)
        if self._matches(probe):
            return True
        # The path itself is unique to Lantronix — 401 is a strong signal
        if probe is not None and probe.status_code == 401:
            return True
        return False

    # Default Basic Auth try_login() inherited from Service.
