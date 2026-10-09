"""Box des fournisseurs d'accès français : Bouygues, Free, Orange, SFR."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from .base import (BoxApprovalRequired, BoxAuthError, BoxError, BoxProvider, host_allowed)
from .bouygues import BouyguesProvider
from .freebox import FreeboxProvider
from .livebox import LiveboxProvider
from .sfr import SfrProvider

PROVIDERS: dict[str, type[BoxProvider]] = {
    p.id: p for p in (BouyguesProvider, FreeboxProvider, LiveboxProvider, SfrProvider)
}

__all__ = ["PROVIDERS", "BoxApprovalRequired", "BoxAuthError", "BoxError", "BoxProvider", "detect",
           "host_allowed", "provider_list"]


def provider_list() -> list[dict]:
    return [cls.info() for cls in PROVIDERS.values()]


def detect(host: str, timeout: float = 3.0) -> list[dict]:
    """Interroge `host` avec chaque fournisseur (sans identifiants) et renvoie ceux qui reconnaissent la box."""
    if not host_allowed(host):
        return []

    def one(cls):
        try:
            p = cls(host)
            p.http.timeout = timeout
            res = cls.probe(host, p.http)
        except Exception:  # noqa: BLE001 - une sonde ne doit jamais faire échouer la détection
            return None
        return {"provider": cls.id, "label": cls.label, "model": res.get("model"), "host": host} if res else None

    with ThreadPoolExecutor(max_workers=len(PROVIDERS)) as ex:
        found = [r for r in ex.map(one, PROVIDERS.values()) if r]
    return found
