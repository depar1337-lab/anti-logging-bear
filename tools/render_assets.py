# Anti-Logging Bear by Priest

from __future__ import annotations

import io
import sys
from pathlib import Path

import resvg_py
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))
import barry  # noqa: E402
import pixel_bear  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "assets-src"
OUT = ROOT / "src" / "antiloggingbear" / "assets"
WEB_ICONS = ROOT / "web" / "icons"
WEB_IMAGES = ROOT / "web" / "img"
DARK_GROUND = "#141c16"
ICON_BACKGROUND = "#fbf6ea"
PACKAGING = ROOT / "packaging"


def render(svg: str, width: int, height: int) -> Image.Image:
    png = resvg_py.svg_to_bytes(svg_string=svg, width=width, height=height)
    return Image.open(io.BytesIO(bytes(png))).convert("RGBA")


def tile(svg: str, size: int, fill: float = 0.78) -> Image.Image:
    image = Image.new("RGBA", (size, size), ICON_BACKGROUND)
    inner = round(size * fill)
    image.alpha_composite(render(svg, inner, inner), ((size - inner) // 2, (size - inner) // 2))
    return image.convert("RGB")


def write_wizard_images(icons: dict) -> None:
    pose = barry.bear("idle")
    for scale, suffix in ((1, ""), (2, "@2x")):
        width, height = 164 * scale, 314 * scale
        panel = Image.new("RGBA", (width, height), barry.HAT_DARK)
        for y in range(height):
            shade = round(36 * y / height)
            panel.paste((0x24 + shade // 3, 0x49 + shade, 0x2e + shade // 3, 255), (0, y, width, y + 1))
        trees = render(barry.forest_strip(width=330, height=54, ground=ICON_BACKGROUND), 330 * scale // 2, 27 * scale)
        panel.alpha_composite(trees.crop((0, 0, width, trees.height)), (0, height - trees.height))
        bear = render(pose, 140 * scale, 153 * scale)
        panel.alpha_composite(bear, ((width - bear.width) // 2, height - trees.height - bear.height + 10 * scale))
        panel.convert("RGB").save(PACKAGING / f"wizard-large{suffix}.bmp")

        small = Image.new("RGBA", (55 * scale, 58 * scale), ICON_BACKGROUND)
        art = icons[32] if scale == 1 else icons[64]
        small.alpha_composite(art, ((small.width - art.width) // 2, (small.height - art.height) // 2))
        small.convert("RGB").save(PACKAGING / f"wizard-small{suffix}.bmp")


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
    icons = pixel_bear.icon_set()
    icons[512].save(OUT / "icon-512.png", optimize=True)
    icons[64].save(OUT / "tray-64.png", optimize=True)
    icons[32].save(OUT / "icon-32.png", optimize=True)
    ico_sizes = (16, 32, 48, 64, 128, 256)
    icons[256].save(OUT / "app.ico", sizes=[(n, n) for n in ico_sizes],
                    append_images=[icons[n] for n in ico_sizes if n != 256])
    try:
        icons[512].save(OUT / "app.icns", append_images=[icons[n] for n in (16, 32, 64, 128, 256)])
    except (OSError, ValueError) as exc:
        print("skipped app.icns:", exc)
    write_wizard_images(icons)

    WEB_ICONS.mkdir(parents=True, exist_ok=True)
    tile(head, 180).save(WEB_ICONS / "apple-touch-icon.png", optimize=True)
    tile(head, 192).save(WEB_ICONS / "icon-192.png", optimize=True)
    tile(head, 512).save(WEB_ICONS / "icon-512.png", optimize=True)
    icons[32].save(WEB_ICONS / "favicon-32.png", optimize=True)

    strip = barry.forest_strip()
    (SRC / "forest.svg").write_text(strip, encoding="utf-8")
    render(strip, 1200, 54).save(OUT / "forest.png", optimize=True)
    render(barry.forest_strip(ground=DARK_GROUND), 1200, 54).save(WEB_IMAGES / "forest-dark.png", optimize=True)
    print("assets written to", OUT)


if __name__ == "__main__":
    main()
