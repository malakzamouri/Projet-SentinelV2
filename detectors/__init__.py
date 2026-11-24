"""Détecteurs enfichables : une classe décorée par @register suffit pour en ajouter un."""
import time

REGISTRY = []


def register(cls):
    REGISTRY.append(cls)
    return cls


class Detector:
    kinds = ()          # types d'événements traités : "packet", "connection", "process"

    def __init__(self, cfg):
        self.cfg = cfg
        self._seen = {}

    def once(self, *key):
        """Anti-doublons : vrai une seule fois par période de refroidissement."""
        now = time.time()
        if now - self._seen.get(key, 0) < self.cfg.cooldown:
            return False
        self._seen[key] = now
        if len(self._seen) > 10000:
            self._seen = {k: t for k, t in self._seen.items() if now - t < self.cfg.cooldown}
        return True

    def inspect(self, ev):
        return []


from . import behavior, host, integrity, network  # noqa: E402,F401  (enregistre les détecteurs)
