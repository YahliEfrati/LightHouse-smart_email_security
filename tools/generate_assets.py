"""Generates the Lighthouse add-on's static image assets (icons, banners, risk gauges).

Run from the repo root:  python tools/generate_assets.py
Output goes to ./assets/ and is committed, because Gmail card images must be loaded
from a public HTTPS URL (raw.githubusercontent.com).
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional, Tuple

from PIL import Image, ImageDraw, ImageFont

RGB = Tuple[int, int, int]
SS = 4  # supersampling factor for anti-aliasing

STATE_COLORS = {
    "safe": (46, 125, 107),
    "suspicious": (201, 138, 44),
    "malicious": (211, 47, 47),
    "unscanned": (138, 148, 155),
}
BANNER_TEXT = {
    "safe": "ALL CLEAR",
    "suspicious": "CHECK BEFORE YOU ACT",
    "malicious": "DANGER — LIKELY PHISHING",
    "unscanned": "NOT SCANNED",
}
NAVY, YELLOW, WHITE, TOWER_RED, STEEL = (11, 61, 89), (253, 184, 19), (255, 255, 255), (211, 47, 47), (55, 71, 79)
GAUGE_STOPS = ((0, STATE_COLORS["safe"]), (35, STATE_COLORS["suspicious"]), (70, STATE_COLORS["malicious"]))
GAUGE_STEPS = range(0, 91, 5)


def score_color(score: float) -> RGB:
    """Gradient green(0) -> amber(35) -> red(70); clamped outside that range."""
    s = max(0.0, min(100.0, float(score)))
    for (a, ca), (b, cb) in zip(GAUGE_STOPS, GAUGE_STOPS[1:]):
        if s <= b:
            t = (s - a) / (b - a)
            return tuple(round(x + (y - x) * t) for x, y in zip(ca, cb))  # type: ignore[return-value]
    return GAUGE_STOPS[-1][1]


def _font(size: int) -> ImageFont.FreeTypeFont:
    for name in ("arialbd.ttf", "Arial Bold.ttf", "DejaVuSans-Bold.ttf",
                 "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def render_icon(state: str) -> Image.Image:
    """128x128 lighthouse on a dark-blue tile; the beams carry the state color."""
    beam = STATE_COLORS[state]
    n = 128 * SS
    k = SS
    base = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    mask = Image.new("L", (n, n), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, n - 1, n - 1), radius=26 * k, fill=255)
    tile = Image.new("RGBA", (n, n), NAVY + (255,))
    beams = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    bd = ImageDraw.Draw(beams)
    for pts, alpha in (
        ([(64, 40), (6, 22), (6, 58)], 210), ([(64, 40), (122, 22), (122, 58)], 210),
        ([(64, 40), (6, 31), (6, 49)], 235), ([(64, 40), (122, 31), (122, 49)], 235),
    ):
        bd.polygon([(x * k, y * k) for x, y in pts], fill=beam + (alpha,))
    tile = Image.alpha_composite(tile, beams)
    d = ImageDraw.Draw(tile)

    def xl(y: float) -> float: return 58 - 6 * (y - 48) / 52
    def xr(y: float) -> float: return 70 + 6 * (y - 48) / 52
    def band(y1: float, y2: float, fill: RGB) -> None:
        d.polygon([(xl(y1) * k, y1 * k), (xr(y1) * k, y1 * k), (xr(y2) * k, y2 * k), (xl(y2) * k, y2 * k)], fill=fill)

    d.rounded_rectangle((44 * k, 104 * k, 84 * k, 112 * k), radius=2 * k, fill=(176, 190, 197))
    band(48, 104, WHITE)
    band(60, 72, TOWER_RED)
    band(84, 96, TOWER_RED)
    d.rounded_rectangle((53 * k, 44 * k, 75 * k, 48 * k), radius=k, fill=STEEL)
    d.rectangle((57 * k, 34 * k, 71 * k, 44 * k), fill=YELLOW)
    d.polygon([(55 * k, 34 * k), (73 * k, 34 * k), (64 * k, 24 * k)], fill=STEEL)
    base.paste(tile, (0, 0), mask)
    return base.resize((128, 128), Image.LANCZOS)


def render_banner(state: str) -> Image.Image:
    """600x140 full-width state banner: lighthouse icon + bold white message on the state color."""
    w, h = 600, 140
    img = Image.new("RGB", (w * SS, h * SS), STATE_COLORS[state])
    icon = render_icon(state).resize((96 * SS, 96 * SS), Image.LANCZOS)
    img.paste(icon, (22 * SS, 22 * SS), icon)
    font = _font(30 * SS)
    text = BANNER_TEXT[state]
    d = ImageDraw.Draw(img)
    while d.textlength(text, font=font) > (w - 150) * SS and font.size > 12 * SS:
        font = _font(font.size - SS)
    d.text((138 * SS, h * SS // 2), text, font=font, fill=WHITE, anchor="lm")
    return img.resize((w, h), Image.LANCZOS)


def render_gauge(step: Optional[int]) -> Image.Image:
    """600x70 horizontal risk gauge. step=None renders the solid-red alert state (score > 90)."""
    w, h = 600, 70
    x0, x1, y0, y1 = 30, 570, 20, 50
    track = Image.new("RGBA", (w * SS, h * SS), (0, 0, 0, 0))
    td = ImageDraw.Draw(track)
    cols = x1 - x0
    for i in range(cols * SS):
        pos = i / (cols * SS) * 100
        if step is None:
            color = STATE_COLORS["malicious"]
        elif pos <= step:
            color = score_color(pos)
        else:
            c = score_color(pos)
            color = tuple(round(v * 0.28 + 238 * 0.72) for v in c)
        x = x0 * SS + i
        td.line([(x, y0 * SS), (x, y1 * SS)], fill=color + (255,))
    mask = Image.new("L", (w * SS, h * SS), 0)
    ImageDraw.Draw(mask).rounded_rectangle((x0 * SS, y0 * SS, x1 * SS, y1 * SS), radius=15 * SS, fill=255)
    out = Image.new("RGBA", (w * SS, h * SS), (0, 0, 0, 0))
    out.paste(track, (0, 0), mask)
    if step is not None:
        cx = (x0 + cols * step / 100) * SS
        cy = (y0 + y1) / 2 * SS
        r = 17 * SS
        ring = score_color(step)
        ImageDraw.Draw(out).ellipse((cx - r, cy - r, cx + r, cy + r), fill=WHITE + (255,), outline=ring + (255,), width=5 * SS)
    return out.resize((w, h), Image.LANCZOS)


def main(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for state in STATE_COLORS:
        render_icon(state).save(out_dir / f"icon_{state}.png")
        render_banner(state).save(out_dir / f"banner_{state}.png")
    for step in GAUGE_STEPS:
        render_gauge(step).save(out_dir / f"gauge_{step}.png")
    render_gauge(None).save(out_dir / "gauge_alert.png")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "assets")
