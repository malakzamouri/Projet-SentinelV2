"""Analyse statique d'un fichier : jamais exécuté, lu par blocs."""
import hashlib
import os
from collections import Counter
import math

try:
    import yara
except ImportError:
    yara = None

MAGIC = [(b"MZ", "Exécutable Windows (PE)", True), (b"\x7fELF", "Exécutable Linux (ELF)", True),
         (b"\xcf\xfa\xed\xfe", "Exécutable macOS (Mach-O)", True), (b"#!", "Script exécutable", True),
         (b"PK\x03\x04", "Archive ZIP / Office / APK", False), (b"%PDF", "Document PDF", False)]

# (motif minuscule, points, description)
SIGNATURES = [
    (b"/dev/tcp/", 30, "Reverse shell bash"), (b"nc -e", 30, "Netcat avec exécution"),
    (b"bash -i", 20, "Shell interactif"), (b"base64 -d | sh", 30, "Décodage + exécution"),
    (b"powershell -enc", 30, "PowerShell encodé"), (b"-encodedcommand", 25, "PowerShell encodé"),
    (b"mimikatz", 40, "Vol d'identifiants"), (b"virtualalloc", 10, "Allocation mémoire (injection)"),
    (b"createremotethread", 20, "Injection de code"), (b"writeprocessmemory", 20, "Injection de code"),
    (b"setwindowshookex", 15, "Keylogger possible"), (b"ld_preload", 15, "Détournement de bibliothèques"),
    (b"chmod +x /tmp", 25, "Exécution depuis /tmp"), (b"crontab", 8, "Persistance par cron"),
    (b"your files have been encrypted", 50, "Message de rançongiciel"),
    (b"xmrig", 40, "Mineur de cryptomonnaie"), (b"stratum+tcp", 35, "Pool de minage"),
]


def entropy(data):
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values()) if n else 0.0


class StaticScanner:
    def __init__(self, cfg):
        self.cfg = cfg
        try:
            lines = cfg.hashes_file.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            lines = []
        self.bad_hashes = {l.strip().lower() for l in lines if l.strip() and not l.startswith("#")}
        rules = {p.stem: str(p) for p in cfg.rules_dir.glob("*.yar*")} if cfg.rules_dir.is_dir() else {}
        self.rules, self.rules_error = None, None
        if yara and rules:
            try:
                self.rules = yara.compile(filepaths=rules)
            except yara.Error as e:                       # une règle mal écrite ne doit pas empêcher le démarrage
                self.rules_error = str(e)

    def analyze(self, path):
        sha, md5, sample = hashlib.sha256(), hashlib.md5(), bytearray()
        with open(path, "rb") as f:
            while chunk := f.read(1 << 20):
                sha.update(chunk); md5.update(chunk)
                if len(sample) < self.cfg.read_limit:
                    sample += chunk[: self.cfg.read_limit - len(sample)]
        sample, digest = bytes(sample), sha.hexdigest()

        kind, is_exec = "Type inconnu", False
        for magic, label, ex in MAGIC:
            if sample.startswith(magic):
                kind, is_exec = label, ex
                break
        found = []
        if digest in self.bad_hashes:
            found.append(("Empreinte SHA256 connue comme malveillante", 100))
        ent = entropy(sample)
        if ent >= self.cfg.entropy_packed and (is_exec or kind == "Type inconnu"):
            found.append((f"Entropie très élevée ({ent:.2f}) : fichier packé ou chiffré", 25))
        if is_exec:
            found.append(("Fichier exécutable", 5))
        low, seen = sample.lower(), set()
        for pat, pts, desc in SIGNATURES:
            if pat in low and desc not in seen:
                seen.add(desc)
                found.append((f"{desc} ({pat.decode()})", pts))
        if self.rules:
            try:
                found += [(f"Règle YARA : {m.meta.get('description', m.rule)}", 40) for m in self.rules.match(data=sample)]
            except yara.Error:
                pass

        score = min(100, sum(p for _, p in found))
        return {"sha256": digest, "md5": md5.hexdigest(), "size": os.path.getsize(path), "type": kind,
                "entropy": round(ent, 2), "score": score,
                "verdict": "malveillant" if score >= 70 else "suspect" if score >= 35 else "aucun indice majeur",
                "findings": [{"label": l, "points": p} for l, p in found]}
