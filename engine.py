"""Moteur : reçoit les événements, les distribue aux détecteurs, enregistre les alertes."""
import logging
import queue
import threading
import time
from collections import Counter, defaultdict, deque

from .collectors.capture import Capture
from .collectors.host import HostWatcher
from .detectors import REGISTRY

log = logging.getLogger("sentinel")


class Engine:
    def __init__(self, cfg, store):
        self.cfg, self.store = cfg, store
        self.routes = defaultdict(list)
        for cls in REGISTRY:
            det = cls(cfg)
            for kind in det.kinds:
                self.routes[kind].append(det)
        self.q = queue.Queue(cfg.queue_size)
        self.dropped = 0
        self.lock = threading.Lock()
        self.packets = self.bytes = 0
        self.proto = Counter()
        self.history = deque(maxlen=60)
        self.started = None
        self._stop = threading.Event()
        self.capture = self.watcher = None

    def submit(self, ev):
        try:
            self.q.put_nowait(ev)
        except queue.Full:
            self.dropped += 1                 # on préfère perdre un paquet que saturer la RAM

    def start(self):
        self.started = time.time()
        self.capture = Capture(self.submit, self.cfg.iface, self.cfg.bpf)
        self.watcher = HostWatcher(self.submit, self.cfg.host_interval)
        for t in (self.capture, self.watcher, threading.Thread(target=self._run, daemon=True, name="engine")):
            t.start()

    def stop(self):
        self._stop.set()
        for t in (self.capture, self.watcher):
            if t:
                t.stop()

    def _drain(self):
        batch = []
        try:
            batch.append(self.q.get(timeout=0.5))
            while len(batch) < 1000:
                batch.append(self.q.get_nowait())
        except queue.Empty:
            pass
        return batch

    def process(self, ev):
        for det in self.routes.get(ev["type"], ()):
            try:
                for alert in det.inspect(ev):
                    self.store.add(alert)
            except Exception:  # un détecteur défaillant ne bloque pas les autres
                log.exception("détecteur %s en erreur", type(det).__name__)

    def _run(self):
        t0, sp, sb = time.time(), 0, 0
        while not self._stop.is_set():
            local, size = Counter(), 0
            for ev in self._drain():
                self.process(ev)
                if ev["type"] == "packet":
                    local[ev["proto"]] += 1
                    size += ev["size"]
            n = sum(local.values())
            if n:
                with self.lock:
                    self.packets += n
                    self.bytes += size
                    self.proto.update(local)
                sp, sb = sp + n, sb + size
            now = time.time()
            if now - t0 >= 1:
                with self.lock:
                    self.history.append({"t": now, "pps": round(sp / (now - t0)), "bps": round(sb / (now - t0))})
                t0, sp, sb = now, 0, 0

    def snapshot(self):
        with self.lock:
            base = {"packets": self.packets, "bytes": self.bytes,
                    "protocols": dict(self.proto), "history": list(self.history)}
        return {**base, "running": bool(self.capture and self.capture.is_alive()),
                "error": self.capture.error if self.capture else None, "dropped": self.dropped,
                "uptime": int(time.time() - self.started) if self.started else 0,
                "alert_counts": self.store.counts()}