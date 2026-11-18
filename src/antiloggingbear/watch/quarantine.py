# Anti-Logging Bear by Priest

from __future__ import annotations

import datetime
import json
import os
import shutil
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class QuarantineItem:
    id: str
    original_path: str
    name: str
    sha256: str
    verdict: str
    reason: str
    when: str
    size: int


class Quarantine:
    def __init__(self, folder: Path) -> None:
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)

    def add(self, path: str, sha256: str = "", verdict: str = "", reason: str = "") -> QuarantineItem:
        src = Path(path)
        item = QuarantineItem(
            id=datetime.datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6],
            original_path=str(src.resolve()),
            name=src.name,
            sha256=sha256,
            verdict=verdict,
            reason=reason,
            when=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            size=src.stat().st_size,
        )
        shutil.move(str(src), str(self._blob(item.id)))
        self._meta(item.id).write_text(json.dumps(asdict(item), indent=2), encoding="utf-8")
        return item

    def items(self) -> list[QuarantineItem]:
        out = []
        for meta in sorted(self.folder.glob("*.json"), reverse=True):
            try:
                out.append(QuarantineItem(**json.loads(meta.read_text(encoding="utf-8"))))
            except (OSError, ValueError, TypeError):
                continue
        return out

    def restore(self, item_id: str) -> str:
        item = self._load(item_id)
        target = Path(item.original_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target = target.with_name(f"{target.stem} (restored){target.suffix}")
        shutil.move(str(self._blob(item_id)), str(target))
        self._meta(item_id).unlink()
        return str(target)

    def delete(self, item_id: str) -> None:
        for path in (self._blob(item_id), self._meta(item_id)):
            if path.exists():
                os.remove(str(path))

    def _load(self, item_id: str) -> QuarantineItem:
        return QuarantineItem(**json.loads(self._meta(item_id).read_text(encoding="utf-8")))

    def _blob(self, item_id: str) -> Path:
        return self.folder / f"{item_id}.quarantined"

    def _meta(self, item_id: str) -> Path:
        return self.folder / f"{item_id}.json"
