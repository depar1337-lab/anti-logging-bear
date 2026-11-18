# Anti-Logging Bear by Priest

from __future__ import annotations

from antiloggingbear.watch.quarantine import Quarantine
from antiloggingbear.watch.watcher import FolderWatcher


def test_watcher_waits_for_finished_downloads(tmp_path):
    seen = []
    (tmp_path / "old.zip").write_bytes(b"PK old")
    watcher = FolderWatcher([str(tmp_path)], seen.append)
    for path, sig in watcher._listing():
        watcher._done[path] = sig

    (tmp_path / "mod.zip.crdownload").write_bytes(b"partial")
    (tmp_path / "notes.txt").write_bytes(b"ignored type")
    new = tmp_path / "mod.zip"
    new.write_bytes(b"PK new")
    watcher.poll()
    assert seen == []
    watcher.poll()
    assert seen == [str(new)]
    watcher.poll()
    assert seen == [str(new)]


def test_watcher_exclusions(tmp_path):
    seen = []
    watcher = FolderWatcher([str(tmp_path)], seen.append, exclusions=["setup_*.exe"])
    (tmp_path / "setup_game.exe").write_bytes(b"MZ")
    watcher.poll()
    watcher.poll()
    assert seen == []


def test_quarantine_round_trip(tmp_path):
    vault = Quarantine(tmp_path / "vault")
    target = tmp_path / "downloads" / "bad.zip"
    target.parent.mkdir()
    target.write_bytes(b"PK bad")
    item = vault.add(str(target), "abc", "dangerous", "keylogger")
    assert not target.exists()
    assert [i.name for i in vault.items()] == ["bad.zip"]
    assert not list((tmp_path / "vault").glob("*.zip"))

    target.write_bytes(b"newer file")
    restored = vault.restore(item.id)
    assert restored.endswith("bad (restored).zip")
    assert vault.items() == []
