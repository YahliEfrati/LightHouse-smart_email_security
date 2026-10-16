"""Generates the Lighthouse add-on's static image assets (icons and one "hero" image per score).

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
HEADLINES = {
    "safe": "ALL CLEAR",
    "suspicious": "CHECK BEFORE YOU ACT",
    "malicious": "DANGER — LIKELY MALICIOUS",
    "unscanned": "NOT SCANNED",
}
NAVY, YELLOW, WHITE, TOWER_RED, STEEL = (11, 61, 89), (253, 184, 19), (255, 255, 255), (211, 47, 47), (55, 71, 79)
GAUGE_STOPS = ((0, STATE_COLORS["safe"]), (35, STATE_COLORS["suspicious"]), (70, STATE_COLORS["malicious"]))


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


def state_for_score(score: float) -> str:
    """Mirrors the backend verdict thresholds (backend/analyzer.py: VERDICT_THRESHOLDS)."""
    return "malicious" if score >= 70 else "suspicious" if score >= 35 else "safe"


def _fit_font(draw: ImageDraw.ImageDraw, text: str, size: int, max_width: int) -> ImageFont.FreeTypeFont:
    font = _font(size)
    while draw.textlength(text, font=font) > max_width and font.size > 10 * SS:
        font = _font(font.size - SS)
    return font


def render_hero(score: Optional[int]) -> Image.Image:
    """600x230 hero: state-colored block with the verdict, a big score and the gradient gauge.

    score=None renders the grey "not scanned" variant (no score, no gauge).
    """
    w, h = 600, 230
    state = "unscanned" if score is None else state_for_score(score)
    img = Image.new("RGB", (w * SS, h * SS), STATE_COLORS[state])
    d = ImageDraw.Draw(img)
    icon = render_icon(state).resize((60 * SS, 60 * SS), Image.LANCZOS)
    img.paste(icon, (24 * SS, 16 * SS), icon)
    head = _fit_font(d, HEADLINES[state], 26 * SS, (w - 120) * SS)
    d.text((100 * SS, 46 * SS), HEADLINES[state], font=head, fill=WHITE, anchor="lm")

    if score is None:
        sub = _font(22 * SS)
        d.text((26 * SS, 140 * SS), "No score available.", font=sub, fill=WHITE, anchor="lm")
        d.text((26 * SS, 182 * SS), "Use your usual caution.", font=sub, fill=WHITE, anchor="lm")
        return img.resize((w, h), Image.LANCZOS)

    big = _font(92 * SS)
    d.text((24 * SS, 148 * SS), str(score), font=big, fill=WHITE, anchor="ls")
    num_w = d.textlength(str(score), font=big) / SS
    d.text(((24 + num_w + 10) * SS, 122 * SS), "/ 100", font=_font(24 * SS), fill=WHITE, anchor="ls")
    d.text(((24 + num_w + 10) * SS, 148 * SS), "RISK SCORE", font=_font(14 * SS), fill=WHITE, anchor="ls")

    # Gauge on a white pill so the gradient keeps its true colors on any state color.
    d.rounded_rectangle((24 * SS, 164 * SS, 576 * SS, 208 * SS), radius=22 * SS, fill=WHITE)
    x0, x1, y0, y1 = 38, 562, 176, 196
    cols = x1 - x0
    alert = score > 90
    for i in range(cols * SS):
        pos = i / (cols * SS) * 100
        if alert:
            color = STATE_COLORS["malicious"]
        elif pos <= score:
            color = score_color(pos)
        else:
            color = tuple(round(v * 0.28 + 238 * 0.72) for v in score_color(pos))
        x = x0 * SS + i
        d.line([(x, y0 * SS), (x, y1 * SS)], fill=color)
    cx, cy, r = (x0 + cols * score / 100) * SS, (y0 + y1) / 2 * SS, 12 * SS
    ring = STATE_COLORS["malicious"] if alert else score_color(score)
    d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=WHITE, outline=ring, width=4 * SS)
    return img.resize((w, h), Image.LANCZOS)


def main(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for state in STATE_COLORS:
        render_icon(state).save(out_dir / f"icon_{state}.png")
    for score in range(0, 101):
        render_hero(score).save(out_dir / f"hero_{score}.png")
    render_hero(None).save(out_dir / "hero_unscanned.png")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "assets")
