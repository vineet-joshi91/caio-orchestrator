from .cfo import run as CFO
from .chro import run as CHRO
from .coo import run as COO
from .cmo import run as CMO
from .cpo import run as CPO

brain_registry = {
    "CFO": CFO,
    "CHRO": CHRO,
    "COO": COO,
    "CMO": CMO,
    "CPO": CPO,
}
