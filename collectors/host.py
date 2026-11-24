"""Surveille la machine : connexions actives et processus, à intervalle régulier."""
import threading

import psutil


def list_connections():
    names, out = {}, []
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return out
    for c in conns:
        if c.pid and c.pid not in names:
            try:
                names[c.pid] = psutil.Process(c.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                names[c.pid] = None
        out.append({"pid": c.pid, "process": names.get(c.pid), "status": c.status,
                    "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "remote_ip": c.raddr.ip if c.raddr else None,
                    "remote_port": c.raddr.port if c.raddr else None})
    return out


class HostWatcher(threading.Thread):
    def __init__(self, submit, interval):
        super().__init__(daemon=True, name="host-watcher")
        self.submit, self.interval = submit, interval
        self._stop_evt = threading.Event()

    def stop(self):
        self._stop_evt.set()

    def run(self):
        while not self._stop_evt.wait(self.interval):
            for c in list_connections():
                if c["remote_ip"]:
                    self.submit({"type": "connection", **c})
            for p in psutil.process_iter(["pid", "name", "exe", "cpu_percent"]):
                try:
                    self.submit({"type": "process", "pid": p.info["pid"], "name": p.info["name"], "exe": p.info["exe"],
                                 "cpu": p.info["cpu_percent"]})
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
