"""Surveillance d'intégrité : compare les dossiers surveillés à une référence de hashs SHA256."""
import hashlib
import json
import os
import threading
from pathlib import Path


def sha256(chemin):
    h = hashlib.sha256()
    with open(chemin, "rb") as f:
        for bloc in iter(lambda: f.read(1 << 20), b""):       # lecture par blocs : faible RAM
            h.update(bloc)
    return h.hexdigest()


def scanner_dossiers(dossiers):
    """{chemin: sha256} de tous les fichiers réguliers (liens symboliques ignorés)."""
    etat = {}
    for dossier in dossiers:
        for racine, _sous, fichiers in os.walk(dossier):
            for nom in fichiers:
                chemin = os.path.join(racine, nom)
                if os.path.islink(chemin):
                    continue
                try:
                    etat[chemin] = sha256(chemin)
                except OSError:                                # fichier disparu ou illisible
                    continue
    return etat


def creer_reference(dossiers, sortie):
    etat = scanner_dossiers(dossiers)
    Path(sortie).write_text(json.dumps(etat, indent=1), encoding="utf-8")
    return len(etat)


def comparer(reference, etat):
    """Retourne [(type, chemin)] avec type = nouveau | modifie | supprime."""
    chg = [("nouveau", p) for p in etat if p not in reference]
    chg += [("modifie", p) for p, h in etat.items() if p in reference and reference[p] != h]
    chg += [("supprime", p) for p in reference if p not in etat]
    return chg


class IntegrityWatcher(threading.Thread):
    def __init__(self, submit, cfg, scanner=None):
        super().__init__(daemon=True, name="integrity")
        self.submit, self.cfg, self.scanner = submit, cfg, scanner
        self._stop_evt = threading.Event()
        self._signales = set()          # changements déjà signalés : pas d'alerte répétée à chaque tour
        self._ref_mtime = None
        self._prevenu = False

    def stop(self):
        self._stop_evt.set()

    def verifier(self):
        ref_path = self.cfg.integrity_ref
        if not ref_path.exists():
            if not self._prevenu:                             # un seul avertissement
                self._prevenu = True
                self.submit({"type": "file_change", "change": "sans_reference",
                             "path": ", ".join(self.cfg.watched_dirs)})
            return
        mtime = ref_path.stat().st_mtime
        if mtime != self._ref_mtime:                          # référence recréée : on repart de zéro
            self._ref_mtime, self._signales = mtime, set()
        reference = json.loads(ref_path.read_text(encoding="utf-8"))
        etat = scanner_dossiers(self.cfg.watched_dirs)
        for typ, chemin in comparer(reference, etat):
            cle = (typ, chemin, etat.get(chemin))
            if cle in self._signales:
                continue
            self._signales.add(cle)
            ev = {"type": "file_change", "change": typ, "path": chemin}
            if self.scanner and typ != "supprime":            # YARA + signatures sur le fichier changé
                try:
                    r = self.scanner.analyze(chemin)
                    ev.update(score=r["score"], verdict=r["verdict"])
                except OSError:
                    pass
            self.submit(ev)

    def run(self):
        while True:
            try:
                self.verifier()
            except Exception:  # noqa: BLE001  (un fichier illisible ne doit pas tuer la surveillance)
                pass
            if self._stop_evt.wait(self.cfg.integrity_interval):
                break
