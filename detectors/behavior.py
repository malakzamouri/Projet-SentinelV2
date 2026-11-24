from collections import defaultdict

from ..models import HIGH, MEDIUM, Alert
from . import Detector, register


@register
class HostBehavior(Detector):
    kinds = ("process",)

    def __init__(self, cfg):
        super().__init__(cfg)
        self.streak = defaultdict(int)      # pid -> nombre de contrôles consécutifs au-dessus du seuil

    def inspect(self, ev):
        pid, nom, cpu, alerts = ev["pid"], (ev["name"] or "").lower(), ev.get("cpu") or 0.0, []
        if any(m in nom for m in self.cfg.miner_names) and self.once("miner", pid):
            alerts.append(Alert(HIGH, "Mineur probable", f"Le processus {nom} (pid {pid}) porte le nom d'un mineur de cryptomonnaie"))
        if cpu >= self.cfg.cpu_threshold:
            if len(self.streak) > 5000:
                self.streak.clear()
            self.streak[pid] += 1
            if self.streak[pid] >= self.cfg.cpu_checks and self.once("cpu", pid):
                duree = self.cfg.cpu_checks * self.cfg.host_interval
                alerts.append(Alert(MEDIUM, "CPU anormal", f"{nom} (pid {pid}) utilise {cpu:.0f}% du CPU depuis ~{duree}s"))
        else:
            self.streak.pop(pid, None)
        return alerts
