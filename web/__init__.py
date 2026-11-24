import os
import socket
import tempfile

import psutil
from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

from ..collectors.host import list_connections
from ..scanner.quarantine import Quarantine
from ..scanner.static import StaticScanner


def create_app(cfg, engine, store):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = cfg.max_upload_mb * 1024 * 1024
    scanner, quarantine = StaticScanner(cfg), Quarantine(cfg.quarantine_dir)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/status")
    def status():
        return jsonify(engine.snapshot())

    @app.get("/api/alerts")
    def alerts():
        return jsonify(store.list(request.args.get("since", 0, type=int)))

    @app.post("/api/alerts/clear")
    def clear():
        store.clear()
        return jsonify(ok=True)

    @app.get("/api/connections")
    def connections():
        rows = []
        for c in list_connections():
            ip, port = c["remote_ip"], c["remote_port"]
            why = ("IP en liste noire" if ip in cfg.bad_ips else
                   f"Port suspect : {cfg.suspicious_ports[port]}" if port in cfg.suspicious_ports else None)
            rows.append({"process": c["process"], "pid": c["pid"], "local": c["local"], "status": c["status"],
                         "remote": f"{ip}:{port}" if ip else "", "suspicious": why})
        return jsonify(rows)

    @app.get("/api/interfaces")
    def interfaces():
        io, addrs = psutil.net_io_counters(pernic=True), psutil.net_if_addrs()
        return jsonify([{"name": n, "up": s.isup,
                         "ips": [a.address for a in addrs.get(n, []) if a.family in (socket.AF_INET, socket.AF_INET6)],
                         "bytes_recv": io[n].bytes_recv if n in io else 0,
                         "bytes_sent": io[n].bytes_sent if n in io else 0}
                        for n, s in psutil.net_if_stats().items()])

    @app.post("/api/scan")
    def scan():
        f = request.files.get("file")
        if not f or not f.filename:
            return jsonify(error="Aucun fichier reçu."), 400
        fd, tmp = tempfile.mkstemp(prefix="sentinel_")      # droits 0600 : jamais exécutable
        os.close(fd)
        kept = False
        try:
            f.save(tmp)
            report = scanner.analyze(tmp)
            report["filename"] = secure_filename(f.filename)
            if request.form.get("quarantine") == "1" and report["score"] >= cfg.quarantine_score:
                quarantine.add(tmp, report["filename"], report)
                report["quarantined"] = kept = True
            return jsonify(report)
        finally:
            if not kept and os.path.exists(tmp):
                os.remove(tmp)                               # le fichier n'est jamais conservé sinon

    @app.get("/api/quarantine")
    def q_list():
        return jsonify(quarantine.list())

    @app.delete("/api/quarantine/<sha>")
    def q_delete(sha):
        return (jsonify(ok=True), 200) if quarantine.delete(sha) else (jsonify(error="Introuvable"), 404)

    @app.errorhandler(413)
    def too_big(_e):
        return jsonify(error=f"Fichier trop volumineux (max {cfg.max_upload_mb} Mo)."), 413

    return app
