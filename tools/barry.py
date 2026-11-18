# Anti-Logging Bear by Priest

from __future__ import annotations

INK = "#3a2414"
FUR = "#8c5a32"
FUR_DARK = "#70462a"
MUZZLE = "#f3dfbb"
EAR = "#e3b089"
NOSE = "#2a1810"
HAT = "#2f7d3b"
HAT_DARK = "#1f5a29"
STRAP = "#6b3d1f"
FEATHER = "#d63b2b"
FEATHER_DARK = "#8f1f17"
CHEEK = "#e88c6a"
LEAF = "#4caf50"
SICK = "#9cc23e"
SICK_DARK = "#5f7f1c"
SICK_LIGHT = "#cfe07a"

W = f'stroke="{INK}" stroke-width="6" stroke-linejoin="round" stroke-linecap="round"'


def _limb(x1, y1, x2, y2, paw=True):
    out = [
        f'<path d="M{x1} {y1} L{x2} {y2}" stroke="{INK}" stroke-width="58" stroke-linecap="round"/>',
        f'<path d="M{x1} {y1} L{x2} {y2}" stroke="{FUR}" stroke-width="46" stroke-linecap="round"/>',
    ]
    if paw:
        out.append(_paw(x2, y2))
    return "".join(out)


def _paw(x, y):
    return (f'<circle cx="{x}" cy="{y}" r="25" fill="{FUR}" {W}/>'
            f'<ellipse cx="{x}" cy="{y + 3}" rx="12" ry="9" fill="{MUZZLE}"/>')


def _hat():
    return "".join([
        f'<path d="M108 120 C112 52 186 22 250 34 C292 42 322 36 352 16 '
        f'C344 58 318 96 294 120 Z" fill="{HAT}" {W}/>',
        f'<path d="M250 34 C292 42 322 36 352 16 C330 44 306 60 280 66 Z" fill="{HAT_DARK}" opacity="0.55"/>',
        f'<path d="M156 104 C128 64 102 34 66 12 C104 20 142 48 170 100 Z" fill="{FEATHER}" {W}/>',
        f'<path d="M163 102 Q118 54 72 16" fill="none" stroke="{FEATHER_DARK}" stroke-width="4" stroke-linecap="round"/>',
        f'<path d="M96 126 C150 96 250 96 304 126 L300 144 C250 116 150 116 100 144 Z" fill="{HAT_DARK}" {W}/>',
    ])


def _ears():
    return "".join([
        f'<circle cx="112" cy="128" r="31" fill="{FUR}" {W}/>',
        f'<circle cx="288" cy="128" r="31" fill="{FUR}" {W}/>',
        f'<circle cx="114" cy="132" r="16" fill="{EAR}"/>',
        f'<circle cx="286" cy="132" r="16" fill="{EAR}"/>',
    ])


def _face(mood):
    eyes = "".join([
        f'<ellipse cx="166" cy="166" rx="14" ry="17" fill="#fff" {W}/>',
        f'<ellipse cx="234" cy="166" rx="14" ry="17" fill="#fff" {W}/>',
    ])
    if mood == "sick":
        pupils = (f'<path d="M154 156 L178 166 L154 176" fill="none" stroke="{INK}" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>'
                  f'<path d="M246 156 L222 166 L246 176" fill="none" stroke="{INK}" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>')
        eyes = ""
    elif mood == "queasy":
        pupils = "".join([
            f'<circle cx="166" cy="172" r="7" fill="{INK}"/>',
            f'<circle cx="234" cy="172" r="7" fill="{INK}"/>',
            f'<path d="M151 162 Q166 156 181 162" fill="{FUR}" stroke="{INK}" stroke-width="5" stroke-linecap="round"/>',
            f'<path d="M219 162 Q234 156 249 162" fill="{FUR}" stroke="{INK}" stroke-width="5" stroke-linecap="round"/>',
        ])
    elif mood == "happy":
        pupils = (f'<path d="M154 168 Q166 152 178 168" fill="none" stroke="{INK}" stroke-width="7" stroke-linecap="round"/>'
                  f'<path d="M222 168 Q234 152 246 168" fill="none" stroke="{INK}" stroke-width="7" stroke-linecap="round"/>')
        eyes = ""
    else:
        dy = -3 if mood == "alarm" else 2
        pupils = "".join([
            f'<circle cx="168" cy="{168 + dy}" r="8" fill="{INK}"/>',
            f'<circle cx="232" cy="{168 + dy}" r="8" fill="{INK}"/>',
            f'<circle cx="171" cy="{164 + dy}" r="3" fill="#fff"/>',
            f'<circle cx="235" cy="{164 + dy}" r="3" fill="#fff"/>',
        ])
    brows = {
        "idle": "M150 140 Q165 132 180 138 M220 138 Q235 132 250 140",
        "scan": "M150 142 Q165 138 180 142 M220 136 Q235 128 250 134",
        "happy": "M150 136 Q165 126 180 134 M220 134 Q235 126 250 136",
        "worried": "M150 148 Q164 142 180 132 M220 132 Q236 142 250 148",
        "alarm": "M150 134 Q166 140 182 148 M218 148 Q234 140 250 134",
        "queasy": "M150 146 Q164 140 180 136 M220 136 Q236 140 250 146",
        "sick": "M150 136 Q166 144 182 150 M218 150 Q234 144 250 136",
    }[mood]
    mouth = {
        "idle": f'<path d="M184 220 Q200 236 216 220" fill="none" stroke="{INK}" stroke-width="6" stroke-linecap="round"/>',
        "scan": f'<path d="M188 224 Q200 230 212 222" fill="none" stroke="{INK}" stroke-width="6" stroke-linecap="round"/>',
        "happy": (f'<path d="M178 216 Q200 252 222 216 Z" fill="#7a2a20" {W}/>'
                  f'<path d="M189 232 Q200 242 211 232 Q200 226 189 232 Z" fill="#e86a5a"/>'),
        "worried": f'<path d="M184 226 Q192 218 200 226 Q208 234 216 226" fill="none" stroke="{INK}" stroke-width="6" stroke-linecap="round"/>',
        "alarm": f'<ellipse cx="200" cy="228" rx="13" ry="15" fill="#7a2a20" {W}/>',
        "queasy": (f'<path d="M180 228 Q188 218 196 228 Q204 238 212 228 Q218 220 222 226" fill="none" '
                   f'stroke="{INK}" stroke-width="6" stroke-linecap="round"/>'),
        "sick": f'<ellipse cx="200" cy="230" rx="20" ry="17" fill="#7a2a20" {W}/>',
    }[mood]
    tint = ""
    if mood in ("queasy", "sick"):
        tint = (f'<ellipse cx="200" cy="208" rx="50" ry="38" fill="{SICK}" opacity="0.45"/>'
                f'<ellipse cx="146" cy="204" rx="15" ry="10" fill="{SICK}" opacity="0.7"/>'
                f'<ellipse cx="254" cy="204" rx="15" ry="10" fill="{SICK}" opacity="0.7"/>')
    return "".join([
        f'<ellipse cx="200" cy="208" rx="50" ry="38" fill="{MUZZLE}" {W}/>',
        f'<ellipse cx="146" cy="204" rx="14" ry="9" fill="{CHEEK}" opacity="0.5"/>',
        f'<ellipse cx="254" cy="204" rx="14" ry="9" fill="{CHEEK}" opacity="0.5"/>',
        tint, eyes, pupils,
        f'<path d="{brows}" fill="none" stroke="{INK}" stroke-width="7" stroke-linecap="round"/>',
        f'<path d="M184 190 Q200 180 216 190 Q214 204 200 207 Q186 204 184 190 Z" fill="{NOSE}"/>',
        '<ellipse cx="194" cy="189" rx="5" ry="3" fill="#fff" opacity="0.6"/>',
        f'<path d="M200 206 L200 214" stroke="{INK}" stroke-width="5" stroke-linecap="round"/>',
        mouth,
    ])


def _body():
    return "".join([
        f'<ellipse cx="148" cy="428" rx="40" ry="22" fill="{FUR}" {W}/>',
        f'<ellipse cx="252" cy="428" rx="40" ry="22" fill="{FUR}" {W}/>',
        f'<ellipse cx="148" cy="431" rx="20" ry="10" fill="{MUZZLE}"/>',
        f'<ellipse cx="252" cy="431" rx="20" ry="10" fill="{MUZZLE}"/>',
        f'<path d="M200 248 C280 248 304 320 300 370 C296 420 254 436 200 436 '
        f'C146 436 104 420 100 370 C96 320 120 248 200 248 Z" fill="{FUR}" {W}/>',
        f'<ellipse cx="200" cy="362" rx="58" ry="62" fill="{MUZZLE}"/>',
        f'<path d="M136 276 L288 404" stroke="{INK}" stroke-width="24" stroke-linecap="round"/>',
        f'<path d="M136 276 L288 404" stroke="{STRAP}" stroke-width="14" stroke-linecap="round"/>',
        f'<path d="M212 318 C222 296 248 292 258 300 C252 322 232 334 212 318 Z" fill="{LEAF}" {W}/>',
        f'<path d="M214 316 L250 302" stroke="{INK}" stroke-width="3"/>',
    ])


def _head(mood):
    return _ears() + f'<circle cx="200" cy="176" r="94" fill="{FUR}" {W}/>' + _face(mood) + _hat()


def _magnifier():
    return "".join([
        f'<path d="M300 352 L326 296" stroke="{INK}" stroke-width="20" stroke-linecap="round"/>',
        f'<path d="M300 352 L326 296" stroke="{STRAP}" stroke-width="10" stroke-linecap="round"/>',
        f'<circle cx="344" cy="256" r="44" fill="#bfe3f2" fill-opacity="0.45" stroke="{INK}" stroke-width="16"/>',
        '<circle cx="344" cy="256" r="44" fill="none" stroke="#c9a46a" stroke-width="8"/>',
        '<path d="M318 236 Q328 220 346 218" fill="none" stroke="#fff" stroke-width="6" stroke-linecap="round"/>',
    ])


def _sign():
    font = 'font-family="Arial Black, Arial, Helvetica, sans-serif" font-weight="900" text-anchor="middle" fill="#fff"'
    return "".join([
        f'<path d="M200 370 L200 448" stroke="{INK}" stroke-width="22" stroke-linecap="round"/>',
        f'<path d="M200 370 L200 448" stroke="{STRAP}" stroke-width="12" stroke-linecap="round"/>',
        f'<rect x="78" y="286" width="244" height="96" rx="10" fill="#c62f24" {W}/>',
        '<rect x="88" y="296" width="224" height="76" rx="6" fill="none" stroke="#fff" stroke-width="3" opacity="0.8"/>',
        f'<text x="200" y="330" font-size="27" {font}>STOP THE</text>',
        f'<text x="200" y="362" font-size="30" {font}>LOGGERS</text>',
    ])


def _thumb(x, y):
    return "".join([
        f'<circle cx="{x}" cy="{y}" r="27" fill="{FUR}" {W}/>',
        f'<rect x="{x - 10}" y="{y - 58}" width="22" height="40" rx="11" fill="{FUR}" {W}/>',
        f'<path d="M{x - 18} {y - 6} L{x + 18} {y - 6} M{x - 18} {y + 6} L{x + 18} {y + 6}" stroke="{INK}" stroke-width="4" stroke-linecap="round"/>',
    ])


def _drop():
    return (f'<path d="M318 112 C318 112 300 136 300 148 C300 158 308 164 318 164 '
            f'C328 164 336 158 336 148 C336 136 318 112 318 112 Z" fill="#7cc4e8" {W}/>')


def _wobble():
    return "".join(
        f'<path d="M{x} {y} q8 -10 16 0 t16 0" fill="none" stroke="{SICK_DARK}" stroke-width="5" stroke-linecap="round"/>'
        for x, y in ((48, 150), (334, 168), (40, 196))
    )


def _vomit():
    return "".join([
        f'<path d="M184 236 C176 262 196 282 220 300 C252 324 270 356 268 392 C267 410 270 424 276 430 '
        f'L330 430 C318 412 306 396 300 370 C292 330 262 296 236 270 C224 258 220 246 218 236 Z" fill="{SICK}" {W}/>',
        f'<path d="M200 248 C206 270 236 292 256 318 C272 340 280 368 284 400" fill="none" stroke="{SICK_LIGHT}" '
        f'stroke-width="7" stroke-linecap="round" opacity="0.8"/>',
        f'<path d="M236 444 C226 428 252 418 290 420 C330 418 382 422 392 434 C398 448 356 452 300 452 '
        f'C262 452 240 452 236 444 Z" fill="{SICK}" {W}/>',
        f'<circle cx="262" cy="350" r="6" fill="{SICK_LIGHT}" stroke="{SICK_DARK}" stroke-width="3"/>',
        f'<circle cx="236" cy="300" r="5" fill="#e3a23a" stroke="{SICK_DARK}" stroke-width="3"/>',
        f'<circle cx="290" cy="396" r="5" fill="#e3a23a" stroke="{SICK_DARK}" stroke-width="3"/>',
        f'<circle cx="340" cy="436" r="6" fill="{SICK_LIGHT}" stroke="{SICK_DARK}" stroke-width="3"/>',
        f'<circle cx="372" cy="432" r="4" fill="#e3a23a" stroke="{SICK_DARK}" stroke-width="2"/>',
        f'<path d="M354 408 q6 -8 12 0 M380 402 q6 -8 12 0" fill="none" stroke="{SICK_DARK}" stroke-width="4" stroke-linecap="round"/>',
    ])


POSES = ("idle", "scan", "happy", "worried", "alarm")
WEB_POSES = ("queasy", "sick")


def bear(pose: str) -> str:
    parts = []
    if pose == "idle":
        parts += [_body(), _limb(120, 296, 104, 372), _limb(280, 292, 340, 218), _head("idle")]
    elif pose == "scan":
        parts += [_body(), _limb(120, 296, 108, 372), _magnifier(), _limb(280, 296, 300, 352), _head("scan")]
    elif pose == "happy":
        parts += [_body(), _limb(120, 296, 104, 372), _limb(280, 292, 330, 260, paw=False), _thumb(334, 254),
                  _head("happy")]
    elif pose == "worried":
        parts += [_body(), _limb(124, 300, 168, 276), _limb(276, 300, 232, 276), _head("worried"), _drop()]
    elif pose == "alarm":
        parts += [_body(), _limb(124, 300, 84, 350, paw=False), _limb(276, 300, 316, 350, paw=False), _sign(),
                  _paw(84, 352), _paw(316, 352), _head("alarm")]
    elif pose == "queasy":
        parts += [_body(), _limb(124, 300, 172, 352), _limb(276, 300, 228, 352), _head("queasy"), _wobble()]
    elif pose == "sick":
        parts += [_body(), _limb(124, 300, 172, 352), _limb(276, 300, 228, 352), _head("sick"), _vomit()]
    else:
        raise ValueError(pose)
    return _svg("0 0 420 460", "".join(parts))


def head_icon() -> str:
    return _svg("56 4 304 304", _head("idle"))


def forest_strip(width: int = 1200, height: int = 54, ground: str = "#fbf6ea") -> str:
    import random
    rng = random.Random(7)
    layers = [("#2c5838", 0.55), ("#33623f", 0.8), (ground, 0.42)]
    shapes = []
    for colour, scale in layers:
        x = -20.0
        while x < width + 40:
            h = rng.uniform(46, 64) * scale
            w = h * 0.6
            shapes.append(f'<path d="M{x:.0f} {height} L{x + w / 2:.0f} {height - h:.0f} L{x + w:.0f} {height} Z" fill="{colour}"/>')
            x += w * rng.uniform(0.5, 0.9) if colour != ground else w * rng.uniform(0.8, 2.6)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}">'
            + "".join(shapes) + "</svg>")


def _svg(view_box: str, body: str) -> str:
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view_box}">{body}</svg>'
