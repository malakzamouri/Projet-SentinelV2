import math
from collections import Counter, defaultdict, deque

from ..models import HIGH, MEDIUM, Alert
from . import Detector, register


def is_syn(ev):
    return ev["proto"] == "TCP" and ev["flags"] & 0x02 and not ev["flags"] & 0x10


def entropy(s):
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values()) if n else 0.0


@register
class PortScan(Detector):
    kinds = ("packet",)

    def __init__(self, cfg):
        super().__init__(cfg)
        self.seen = defaultdict(lambda: deque(maxlen=2000))

    def inspect(self, ev):
        if not is_syn(ev):
            return []
        if len(self.seen) > 5000:
            self.seen.clear()                                # borne mémoire
        dq, now = self.seen[ev["src"]], ev["ts"]
        dq.append((now, ev["dport"]))
        while dq and now - dq[0][0] > self.cfg.portscan_window:
            dq.popleft()
        n = len({p for _, p in dq})
        if n >= self.cfg.portscan_ports and self.once("scan", ev["src"]):
            return [Alert(HIGH, "Scan de ports", f"{n} ports sondés en {self.cfg.portscan_window}s", ev["src"], ev["dst"])]
        return []


@register
class SynFlood(Detector):
    kinds = ("packet",)

    def __init__(self, cfg):
        super().__init__(cfg)
        self.seen = defaultdict(lambda: deque(maxlen=5000))

    def inspect(self, ev):
        if not is_syn(ev):
            return []
        if len(self.seen) > 5000:
            self.seen.clear()
        dq, now = self.seen[ev["dst"]], ev["ts"]
        dq.append(now)
        while dq and now - dq[0] > self.cfg.synflood_window:
            dq.popleft()
        if len(dq) >= self.cfg.synflood_count and self.once("flood", ev["dst"]):
            return [Alert(HIGH, "SYN flood", f"{len(dq)} SYN en {self.cfg.synflood_window}s vers une même cible", None, ev["dst"])]
        return []


@register
class SuspiciousPort(Detector):
    kinds = ("packet",)

    def inspect(self, ev):
        port = ev.get("dport")
        if is_syn(ev) and port in self.cfg.suspicious_ports and self.once("port", ev["src"], ev["dst"], port):
            return [Alert(MEDIUM, "Port suspect", f"Connexion vers le port {port} ({self.cfg.suspicious_ports[port]})", ev["src"], ev["dst"])]
        return []


@register
class Blacklist(Detector):
    kinds = ("packet",)

    def inspect(self, ev):
        if (ev["src"] in self.cfg.bad_ips or ev["dst"] in self.cfg.bad_ips) and self.once("bl", ev["src"], ev["dst"]):
            return [Alert(HIGH, "Liste noire", "Trafic avec une IP en liste noire", ev["src"], ev["dst"])]
        return []


@register
class ArpSpoof(Detector):
    kinds = ("packet",)

    def __init__(self, cfg):
        super().__init__(cfg)
        self.table = {}

    def inspect(self, ev):
        if ev["proto"] != "ARP" or ev.get("arp_op") != 2:
            return []
        ip, mac = ev["src"], ev["arp_mac"]
        old = self.table.get(ip)
        self.table[ip] = mac
        if old and old != mac and self.once("arp", ip):
            return [Alert(HIGH, "ARP spoofing", f"La MAC de {ip} a changé ({old} → {mac})", ip)]
        return []


@register
class DnsAnomaly(Detector):
    kinds = ("packet",)

    def inspect(self, ev):
        q = ev.get("dns_query")
        if not q:
            return []
        d = q.rstrip(".").lower()
        labels, why = d.split("."), []
        if d in self.cfg.bad_domains or any(d.endswith("." + b) for b in self.cfg.bad_domains):
            why.append("domaine en liste noire")
        if len(labels) >= 2 and len(labels[-2]) >= self.cfg.dns_min_label and entropy(labels[-2]) >= self.cfg.dns_entropy:
            why.append("nom à forte entropie (DGA probable)")
        if any(len(x) >= self.cfg.dns_tunnel_label for x in labels):
            why.append("label très long (tunneling probable)")
        if d.endswith(self.cfg.bad_tlds):
            why.append("TLD souvent abusé")
        return [Alert(MEDIUM, "DNS suspect", f"{d} : {w}", ev["src"], ev["dst"])
                for w in why if self.once("dns", d, w)]
