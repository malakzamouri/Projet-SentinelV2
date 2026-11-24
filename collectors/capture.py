"""Capture réseau (scapy, droits root requis). Ne fait que transformer les paquets en événements."""
import threading
import time

from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP, IPv6, sniff


def to_event(pkt):
    ev = {"type": "packet", "ts": time.time(), "size": len(pkt), "proto": "OTHER",
          "src": None, "dst": None, "sport": None, "dport": None, "flags": 0}
    if pkt.haslayer(ARP):
        a = pkt[ARP]
        ev.update(proto="ARP", src=a.psrc, dst=a.pdst, arp_op=int(a.op), arp_mac=a.hwsrc)
        return ev
    ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6] if pkt.haslayer(IPv6) else None
    if ip is None:
        return ev
    ev["src"], ev["dst"] = ip.src, ip.dst
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        ev.update(proto="TCP", sport=t.sport, dport=t.dport, flags=int(t.flags))
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        ev.update(proto="UDP", sport=u.sport, dport=u.dport)
        if pkt.haslayer(DNSQR) and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            q = pkt[DNSQR].qname
            ev.update(proto="DNS", dns_query=q.decode(errors="ignore") if isinstance(q, bytes) else str(q))
    else:
        ev["proto"] = "IP"
    return ev


class Capture(threading.Thread):
    def __init__(self, submit, iface=None, bpf=None):
        super().__init__(daemon=True, name="capture")
        self.submit, self.iface, self.bpf = submit, iface, bpf
        self.error = None
        self._stop_evt = threading.Event()

    def stop(self):
        self._stop_evt.set()

    def run(self):
        def handle(pkt):
            try:
                self.submit(to_event(pkt))
            except Exception:
                pass                          # un paquet mal formé n'arrête jamais la capture
        try:
            sniff(prn=handle, store=False, iface=self.iface, filter=self.bpf or None,
                  stop_filter=lambda _p: self._stop_evt.is_set())
        except PermissionError:
            self.error = "Droits insuffisants : lancez Sentinel avec sudo pour capturer le trafic."
        except Exception as e:  # noqa: BLE001
            self.error = f"Erreur de capture : {e}"
