# Anti-Logging Bear by Priest

from __future__ import annotations

import json
import socket
import threading
from typing import Callable

PORT = 47213
HOST = "127.0.0.1"


def send_to_running(paths: list[str], show: bool = True) -> bool:
    try:
        with socket.create_connection((HOST, PORT), timeout=1.5) as sock:
            sock.sendall(json.dumps({"app": "antiloggingbear", "paths": paths, "show": show}).encode() + b"\n")
            return sock.recv(16).startswith(b"ok")
    except OSError:
        return False


class InstanceServer(threading.Thread):
    def __init__(self, on_message: Callable[[dict], None]) -> None:
        super().__init__(name="instance-server", daemon=True)
        self.on_message = on_message
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def bind(self) -> bool:
        try:
            self.sock.bind((HOST, PORT))
            self.sock.listen(4)
            return True
        except OSError:
            self.sock.close()
            return False

    def run(self) -> None:
        while True:
            try:
                conn, _addr = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.settimeout(2)
                    raw = conn.recv(65536).decode("utf-8", "replace")
                    message = json.loads(raw.splitlines()[0])
                    if message.get("app") == "antiloggingbear":
                        conn.sendall(b"ok")
                        self.on_message(message)
                except (OSError, ValueError, IndexError):
                    continue
