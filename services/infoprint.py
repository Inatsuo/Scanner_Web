import re

from .base import Service


class InfoPrintService(Service):
    name = "InfoPrint"
    creds_filename = "infoprint.creds.json"
    patterns = re.compile(
        r"InfoPrint|Printronix|ptxLogo|LiquidStyles|6700|IPDS|Ricoh|Microplex|emHTTPD",
        re.IGNORECASE,
    )
    config_path = "/indexConf.html"
    # Some InfoPrint firmwares serve a stripped page to non-curl UAs
    user_agent = "curl/8.0.0"

    # Default detect() and try_login() (Basic Auth) inherited from Service.
