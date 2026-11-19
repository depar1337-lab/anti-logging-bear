# Anti-Logging Bear by Priest

from __future__ import annotations

from barry import EAR, FEATHER, FEATHER_DARK, FUR, HAT, HAT_DARK, INK, MUZZLE, NOSE
from PIL import Image, ImageDraw

CHEEK = "#e8957a"
LEAF_LIGHT = "#5fae4f"


def _outline(image: Image.Image) -> None:
    pixels = image.load()
    w, h = image.size
    edge = []
    for y in range(h):
        for x in range(w):
            if pixels[x, y][3] == 0:
                continue
            for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                nx, ny = x + dx, y + dy
                if not (0 <= nx < w and 0 <= ny < h) or pixels[nx, ny][3] == 0:
                    edge.append((x, y))
                    break
    ink = Image.new("RGBA", (1, 1), INK).getpixel((0, 0))
    for point in edge:
        pixels[point] = ink


def bear_32() -> Image.Image:
    image = Image.new("RGBA", (32, 32), (0, 0, 0, 0))
    d = ImageDraw.Draw(image)
    d.ellipse((2, 8, 11, 17), fill=FUR)
    d.ellipse((21, 8, 30, 17), fill=FUR)
    d.ellipse((5, 11, 9, 15), fill=EAR)
    d.ellipse((23, 11, 27, 15), fill=EAR)
    d.ellipse((4, 10, 28, 31), fill=FUR)
    d.ellipse((10, 20, 22, 29), fill=MUZZLE)
    d.polygon([(6, 12), (8, 6), (12, 3), (19, 3), (25, 1), (30, 1), (28, 6), (25, 12)], fill=HAT)
    d.polygon([(19, 3), (25, 1), (30, 1), (27, 4), (22, 5)], fill=HAT_DARK)
    d.rectangle((4, 11, 27, 13), fill=HAT_DARK)
    d.polygon([(12, 11), (6, 5), (1, 0), (4, 0), (10, 5), (14, 10)], fill=FEATHER)
    _outline(image)
    d.line([(3, 0), (12, 10)], fill=FEATHER_DARK)
    d.line([(5, 14), (26, 14)], fill=INK)
    d.rectangle((10, 17, 11, 18), fill=INK)
    d.rectangle((20, 17, 21, 18), fill=INK)
    d.point([(10, 17), (20, 17)], fill="#ffffff")
    d.rectangle((14, 21, 17, 22), fill=NOSE)
    d.point([(15, 23), (16, 23)], fill=NOSE)
    d.line([(13, 25), (14, 26), (17, 26), (18, 25)], fill=INK)
    d.rectangle((7, 21, 8, 22), fill=CHEEK)
    d.rectangle((23, 21, 24, 22), fill=CHEEK)
    d.point([(14, 4), (15, 4), (16, 5)], fill=LEAF_LIGHT)
    return image


def bear_16() -> Image.Image:
    image = Image.new("RGBA", (16, 16), (0, 0, 0, 0))
    d = ImageDraw.Draw(image)
    d.ellipse((0, 4, 5, 9), fill=FUR)
    d.ellipse((10, 4, 15, 9), fill=FUR)
    d.ellipse((1, 5, 14, 15), fill=FUR)
    d.ellipse((4, 10, 11, 15), fill=MUZZLE)
    d.polygon([(3, 6), (4, 3), (7, 1), (11, 1), (14, 1), (13, 3), (12, 6)], fill=HAT)
    d.rectangle((2, 6, 13, 7), fill=HAT_DARK)
    _outline(image)
    d.line([(1, 0), (5, 4)], fill=FEATHER)
    d.point([(4, 9), (11, 9)], fill=INK)
    d.rectangle((7, 10, 8, 11), fill=NOSE)
    d.point([(6, 13), (7, 14), (8, 14), (9, 13)], fill=INK)
    return image


def scaled(image: Image.Image, size: int) -> Image.Image:
    return image.resize((size, size), Image.NEAREST)


def icon_set() -> dict:
    small, large = bear_16(), bear_32()
    return {16: small, 32: large, 48: scaled(small, 48), 64: scaled(large, 64),
            128: scaled(large, 128), 256: scaled(large, 256), 512: scaled(large, 512)}
