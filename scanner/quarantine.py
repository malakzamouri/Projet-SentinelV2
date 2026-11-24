"""Quarantaine : le fichier est déplacé, renommé par son hash et rendu illisible pour l'exécution."""
import json
import os
import re
import shutil
import time
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{64}$")


class Quarantine:
    def __init__(self, directory):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    def add(self, tmp_path, name, report):
        dest = self.dir / f"{report['sha256']}.bin"
        shutil.move(tmp_path, dest)
        os.chmod(dest, 0o400)                       # lecture seule, jamais exécutable
        meta = {"name": name, "sha256": report["sha256"], "verdict": report["verdict"],
                "score": report["score"], "ts": time.time()}
        (self.dir / f"{report['sha256']}.json").write_text(json.dumps(meta), encoding="utf-8")
        return meta

    def list(self):
        items = [json.loads(p.read_text(encoding="utf-8")) for p in self.dir.glob("*.json")]
        return sorted(items, key=lambda m: m["ts"], reverse=True)

    def delete(self, sha):
        if not SHA.match(sha):                      # empêche toute traversée de chemin
            return False
        ok = False
        for ext in ("bin", "json"):
            p = self.dir / f"{sha}.{ext}"
            if p.exists():
                p.unlink(); ok = True
        return ok
