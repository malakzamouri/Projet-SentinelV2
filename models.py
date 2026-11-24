import time
from dataclasses import asdict, dataclass, field

HIGH, MEDIUM, LOW = "high", "medium", "low"


@dataclass
class Alert:
    severity: str
    kind: str
    message: str
    src: str | None = None
    dst: str | None = None
    ts: float = field(default_factory=time.time)
    id: int | None = None

    def to_dict(self):
        return asdict(self)
