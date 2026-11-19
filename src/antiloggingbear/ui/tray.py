# Anti-Logging Bear by Priest

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from .. import APP_NAME
from ..system import paths

if TYPE_CHECKING:
    from ..app import Application


def create_tray(app: Application):
    if sys.platform != "win32":
        return None
    try:
        import pystray
        from PIL import Image
    except ImportError:
        return None

    def later(fn):
        return lambda _icon=None, _item=None: app.post(fn)

    menu = pystray.Menu(
        pystray.MenuItem(f"Open {APP_NAME}", later(app.show_window), default=True),
        pystray.MenuItem("Check a file...", later(app.choose_and_scan)),
        pystray.MenuItem("Check new downloads automatically", later(lambda: app.set_auto_scan(not app.settings.auto_scan)),
                         checked=lambda _item: app.settings.auto_scan),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit", later(app.quit)),
    )
    image = Image.open(paths.asset("tray-64.png"))
    icon = pystray.Icon("barrybear", image, APP_NAME, menu)
    icon.run_detached()
    return icon
