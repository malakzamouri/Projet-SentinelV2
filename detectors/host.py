from ..models import HIGH, MEDIUM, Alert
from . import Detector, register


@register
class HostConnection(Detector):
    kinds = ("connection",)

    def inspect(self, ev):
        ip, port, who = ev["remote_ip"], ev["remote_port"], f"{ev['process'] or 'processus inconnu'} (pid {ev['pid']})"
        if ip in self.cfg.bad_ips and self.once("hc", ev["pid"], ip):
            return [Alert(HIGH, "Connexion suspecte", f"{who} → {ip}:{port} (IP en liste noire)", ev["local"], f"{ip}:{port}")]
        if port in self.cfg.suspicious_ports and self.once("hc", ev["pid"], ip, port):
            return [Alert(MEDIUM, "Connexion suspecte", f"{who} → port {port} ({self.cfg.suspicious_ports[port]})", ev["local"], f"{ip}:{port}")]
        return []


@register
class HostProcess(Detector):
    kinds = ("process",)

    def inspect(self, ev):
        exe, why = ev["exe"] or "", []
        if exe.endswith(" (deleted)"):
            why.append("binaire supprimé du disque pendant l'exécution")
        if exe.startswith(self.cfg.suspicious_dirs):
            why.append("lancé depuis un dossier temporaire")
        if why and self.once("proc", ev["pid"], exe):
            return [Alert(HIGH, "Processus suspect", f"{ev['name']} (pid {ev['pid']}) : {', '.join(why)}")]
        return []