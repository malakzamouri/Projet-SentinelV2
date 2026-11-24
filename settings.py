"""Réglages de Sentinel. Variables d'environnement : SENTINEL_PORT, SENTINEL_IFACE."""
import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Settings:
    host: str = "127.0.0.1"                       # local uniquement
    port: int = int(os.getenv("SENTINEL_PORT", 5000))
    iface: str | None = os.getenv("SENTINEL_IFACE")
    bpf: str = "ip or ip6 or arp"                 # filtre noyau
    data_dir: Path = ROOT / "data"
    queue_size: int = 20000
    cooldown: int = 60                            # secondes entre deux alertes identiques
    host_interval: int = 15                       # contrôle connexions/processus

    portscan_ports: int = 20
    portscan_window: int = 10
    synflood_count: int = 200
    synflood_window: int = 5
    dns_entropy: float = 3.6
    dns_min_label: int = 12
    dns_tunnel_label: int = 40

    max_upload_mb: int = 50
    entropy_packed: float = 7.2
    read_limit: int = 10 * 1024 * 1024
    quarantine_score: int = 70                    # score à partir duquel on propose la quarantaine

    suspicious_ports: dict = field(default_factory=lambda: {
        4444: "Metasploit", 1337: "backdoor courante", 31337: "Back Orifice", 12345: "NetBus",
        6667: "IRC (botnets)", 6697: "IRC TLS (botnets)", 9001: "Tor", 9050: "Tor SOCKS", 5555: "shell distant / ADB"})
    bad_tlds: tuple = (".tk", ".top", ".xyz", ".click", ".gq", ".cf", ".ml", ".work", ".zip")
    bad_ips: set = field(default_factory=set)
    bad_domains: set = field(default_factory=set)
    suspicious_dirs: tuple = ("/tmp/", "/dev/shm/", "/var/tmp/")

    # --- intégrité des fichiers : dossiers surveillés (variable SENTINEL_WATCH="/etc/ssh:/home/moi/site") ---
    watched_dirs: tuple = tuple(d for d in os.getenv("SENTINEL_WATCH", "").split(os.pathsep) if d)
    integrity_interval: int = 60                  # secondes entre deux vérifications

    # --- comportement des processus ---
    cpu_threshold: float = 90.0                   # 100 = un coeur entier
    cpu_checks: int = 3                           # nombre de contrôles consécutifs (3 x host_interval)
    miner_names: tuple = ("xmrig", "minerd", "cpuminer", "ethminer", "nbminer")

    @property
    def db_path(self): return self.data_dir / "sentinel.db"
    @property
    def quarantine_dir(self): return self.data_dir / "quarantine"
    @property
    def hashes_file(self): return self.data_dir / "hashes.txt"
    @property
    def rules_dir(self): return self.data_dir / "rules"
    @property
    def integrity_ref(self): return self.data_dir / "integrity.json"

    def ensure_dirs(self):
        for d in (self.data_dir, self.quarantine_dir, self.rules_dir):
            d.mkdir(parents=True, exist_ok=True)
