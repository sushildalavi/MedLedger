import json
import threading
from pathlib import Path


class ChainStorage:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def read_all(self) -> list[dict]:
        with self._lock:
            return self._read_unlocked()

    def _read_unlocked(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def tip(self) -> dict | None:
        chain = self.read_all()
        return chain[-1] if chain else None

    def append(self, block: dict) -> None:
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(block) + "\n")
