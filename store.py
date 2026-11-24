"""Historique des alertes dans SQLite (persiste après redémarrage)."""
import sqlite3
import threading


class AlertStore:
    def __init__(self, path):
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("""CREATE TABLE IF NOT EXISTS alerts(
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, severity TEXT,
                kind TEXT, message TEXT, src TEXT, dst TEXT)""")
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_ts ON alerts(ts)")
            self.db.commit()

    def add(self, a):
        with self.lock:
            cur = self.db.execute("INSERT INTO alerts(ts,severity,kind,message,src,dst) VALUES(?,?,?,?,?,?)",
                                  (a.ts, a.severity, a.kind, a.message, a.src, a.dst))
            self.db.commit()
            a.id = cur.lastrowid
        return a

    def list(self, since=0, limit=200):
        with self.lock:
            rows = self.db.execute("SELECT * FROM alerts WHERE id>? ORDER BY id DESC LIMIT ?", (since, limit)).fetchall()
        return [dict(r) for r in reversed(rows)]          # du plus ancien au plus récent

    def counts(self):
        with self.lock:
            rows = self.db.execute("SELECT severity, COUNT(*) n FROM alerts GROUP BY severity").fetchall()
        c = {r["severity"]: r["n"] for r in rows}
        return {"high": c.get("high", 0), "medium": c.get("medium", 0), "low": c.get("low", 0)}

    def clear(self):
        with self.lock:
            self.db.execute("DELETE FROM alerts")
            self.db.commit()