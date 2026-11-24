from ..models import HIGH, LOW, MEDIUM, Alert
from . import Detector, register

LIBELLES = {"nouveau": "Nouveau fichier", "modifie": "Fichier modifié", "supprime": "Fichier supprimé"}


@register
class FileChange(Detector):
    kinds = ("file_change",)

    def inspect(self, ev):
        if ev["change"] == "sans_reference":
            return [Alert(LOW, "Intégrité", f"Aucune référence pour {ev['path']} : lancez  python baseline.py")]
        sev = HIGH if ev["change"] == "modifie" else MEDIUM
        suite = ""
        if ev.get("score") is not None and ev["score"] >= 35:      # le fichier change ET paraît dangereux
            sev = HIGH
            suite = f" — analyse : {ev['verdict']} (score {ev['score']}/100)"
        return [Alert(sev, "Intégrité", f"{LIBELLES[ev['change']]} : {ev['path']}{suite}")]
