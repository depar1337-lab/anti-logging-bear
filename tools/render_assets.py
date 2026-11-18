# Anti-Logging Bear by Priest

from __future__ import annotations

import io
import sys
from pathlib import Path

import resvg_py
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))
import barry  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "assets-src"
OUT = ROOT / "src" / "antiloggingbear" / "assets"
WEB_ICONS = ROOT / "web" / "icons"
WEB_IMAGES = ROOT / "web" / "img"
DARK_GROUND = "#141c16"
ICON_BACKGROUND = "#fbf6ea"


def render(svg: str, width: int, height: int) -> Image.Image:
    png = resvg_py.svg_to_bytes(svg_string=svg, width=width, height=height)
    return Image.open(io.BytesIO(bytes(png))).convert("RGBA")


def tile(svg: str, size: int, fill: float = 0.78) -> Image.Image:
    image = Image.new("RGBA", (size, size), ICON_BACKGROUND)
    inner = round(size * fill)
    image.alpha_composite(render(svg, inner, inner), ((size - inner) // 2, (size - inner) // 2))
    return image.convert("RGB")


def main() -> None:
    SRC.mkdir(exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)

    for pose in barry.POSES:
        svg = barry.bear(pose)
        (SRC / f"barry-{pose}.svg").write_text(svg, encoding="utf-8")
        for scale in (1, 2):
            image = render(svg, 210 * scale, 230 * scale)
            suffix = "" if scale == 1 else "@2x"
            image.save(OUT / f"barry-{pose}{suffix}.png", optimize=True)

    WEB_IMAGES.mkdir(parents=True, exist_ok=True)
    for pose in barry.WEB_POSES:
        svg = barry.bear(pose)
        (SRC / f"barry-{pose}.svg").write_text(svg, encoding="utf-8")
        for scale in (1, 2):
            suffix = "" if scale == 1 else "@2x"
            render(svg, 210 * scale, 230 * scale).save(WEB_IMAGES / f"barry-{pose}{suffix}.png", optimize=True)

    head = barry.head_icon()
    (SRC / "barry-head.svg").write_text(head, encoding="utf-8")
    big = render(head, 512, 512)
    big.save(OUT / "icon-512.png", optimize=True)
    render(head, 64, 64).save(OUT / "tray-64.png", optimize=True)
    render(head, 32, 32).save(OUT / "icon-32.png", optimize=True)
    big.save(OUT / "app.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    try:
        big.save(OUT / "app.icns")
    except (OSError, ValueError) as exc:
        print("skipped app.icns:", exc)

    WEB_ICONS.mkdir(parents=True, exist_ok=True)
    tile(head, 180).save(WEB_ICONS / "apple-touch-icon.png", optimize=True)
    tile(head, 192).save(WEB_ICONS / "icon-192.png", optimize=True)
    tile(head, 512).save(WEB_ICONS / "icon-512.png", optimize=True)
    render(head, 32, 32).save(WEB_ICONS / "favicon-32.png", optimize=True)

    strip = barry.forest_strip()
    (SRC / "forest.svg").write_text(strip, encoding="utf-8")
    render(strip, 1200, 54).save(OUT / "forest.png", optimize=True)
    render(barry.forest_strip(ground=DARK_GROUND), 1200, 54).save(WEB_IMAGES / "forest-dark.png", optimize=True)
    print("assets written to", OUT)


if __name__ == "__main__":
    main()
