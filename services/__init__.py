from .ilo import ILOService
from .infoprint import InfoPrintService
from .xport import XPortService
from .sato import SATOService

ALL_SERVICES = [
    ILOService,
    InfoPrintService,
    XPortService,
    SATOService,
]

SERVICES_BY_NAME = {cls.name.lower(): cls for cls in ALL_SERVICES}
