"""Generates the Lighthouse add-on's static image assets (icons and one color-band image per score).

Run from the repo root:  python tools/generate_assets.py
Output goes to ./assets/ and is committed, because Gmail card images must be loaded
from a public HTTPS URL (raw.githubusercontent.com).
"""
from __future__ import annotations

import math
import sys
from pathlib import Path
from typing import Optional, Tuple

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont

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
    "trusted": "TRUSTED SENDER",
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


LAMP = (54, 35)  # lighthouse lamp position inside the 600x146 hero (icon pasted at 24,16, 60px)


def _beam_layer(w: int, h: int, angle: float) -> Image.Image:
    """White light beam from the lamp, as seen while the light turns.

    angle is the rotation around the tower (0 = pointing right, pi/2 = at the viewer): the beam's
    visible length follows cos(angle) and the lamp flares as it faces the viewer.
    """
    size = (w * SS, h * SS)
    layer = Image.new("RGBA", size, (0, 0, 0, 0))
    lx, ly = LAMP[0] * SS, LAMP[1] * SS
    reach = math.cos(angle) * (w - LAMP[0])
    if abs(reach) > 4:
        tip = lx + reach * SS
        length = max(1, round(abs(tip - lx)))
        # Alpha fades from full at the lamp to 0 at this beam's own tip.
        ramp = Image.linear_gradient("L").rotate(90, expand=True).resize((length, size[1]))  # 0 left -> 255 right
        if reach > 0:
            ramp = ramp.transpose(Image.FLIP_LEFT_RIGHT)
        fade = Image.new("L", size, 0)
        fade.paste(ramp, (round(min(lx, tip)), 0))
        light = Image.new("L", size, 0)
        # Wide soft glow plus a bright narrow core reads as a real beam even at sidebar size.
        for half_open, strength, blur in ((8 + 30 * abs(reach) / (w - LAMP[0]), 0.75, 5), (3 + 9 * abs(reach) / (w - LAMP[0]), 1.0, 2)):
            shape = Image.new("L", size, 0)
            ImageDraw.Draw(shape).polygon([(lx, ly - 3 * SS), (tip, ly - half_open * SS), (tip, ly + half_open * SS), (lx, ly + 3 * SS)],
                                          fill=round(255 * strength))
            light = ImageChops.lighter(light, shape.filter(ImageFilter.GaussianBlur(blur * SS)))
        layer = Image.new("RGBA", size, (255, 250, 225, 255))
        layer.putalpha(ImageChops.multiply(light, fade.point(lambda v: min(255, round(v * 1.15)))))
    flare = max(0.0, math.sin(angle))
    if flare > 0.05:
        glow = Image.new("RGBA", size, (0, 0, 0, 0))
        r = (10 + 22 * flare) * SS
        ImageDraw.Draw(glow).ellipse((lx - r, ly - r, lx + r, ly + r), fill=(255, 244, 200, round(235 * flare)))
        glow = glow.filter(ImageFilter.GaussianBlur(7 * SS))
        layer = Image.alpha_composite(layer, glow)
    return layer


def render_hero(score: Optional[int], trusted: bool = False, beam_angle: Optional[float] = None) -> Image.Image:
    """600x146 band: state color, lighthouse, verdict headline and the gradient gauge.

    The score itself is rendered as native text by the add-on (it feels part of the UI),
    so the image only carries color + gauge. score=None renders the grey "not scanned" variant; trusted=True the green "trusted sender" variant (score 0).
    beam_angle adds a sweeping light beam (animation frames only); None is the static image.
    """
    w, h = 600, 146
    state = "trusted" if trusted else "unscanned" if score is None else state_for_score(score)
    if trusted:
        score = 0
    img = Image.new("RGB", (w * SS, h * SS), STATE_COLORS["safe" if trusted else state])
    if beam_angle is not None:
        img = Image.alpha_composite(img.convert("RGBA"), _beam_layer(w, h, beam_angle)).convert("RGB")
    d = ImageDraw.Draw(img)
    icon = render_icon("safe" if trusted else state).resize((60 * SS, 60 * SS), Image.LANCZOS)
    img.paste(icon, (24 * SS, 16 * SS), icon)
    head = _fit_font(d, HEADLINES[state], 26 * SS, (w - 120) * SS)
    d.text((100 * SS, 46 * SS), HEADLINES[state], font=head, fill=WHITE, anchor="lm")

    if score is None:
        d.text((24 * SS, 108 * SS), "No score available — use your usual caution.", font=_fit_font(d, "No score available — use your usual caution.", 20 * SS, (w - 48) * SS), fill=WHITE, anchor="lm")
        return img.resize((w, h), Image.LANCZOS)

    # Gauge on a white pill so the gradient keeps its true colors on any state color.
    d.rounded_rectangle((24 * SS, 88 * SS, 576 * SS, 132 * SS), radius=22 * SS, fill=WHITE)
    x0, x1, y0, y1 = 38, 562, 100, 120
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


def save_hero_animation(path: Path, score: Optional[int], trusted: bool = False, turns: int = 2, frames_per_turn: int = 24) -> None:
    """GIF that plays ONCE: the light makes `turns` full turns, then rests on the exact static hero."""
    frames = turns * frames_per_turn
    angles = [-math.pi / 2 + 2 * math.pi * turns * i / frames for i in range(1, frames)]
    images = [render_hero(score, trusted, beam_angle=a) for a in angles] + [render_hero(score, trusted)]
    # One shared palette built from every frame: no colour shifts between frames, no banding in the beam.
    sheet = Image.new("RGB", (images[0].width, images[0].height * len(images)))
    for i, im in enumerate(images):
        sheet.paste(im, (0, im.height * i))
    palette = sheet.quantize(colors=255, method=Image.Quantize.MEDIANCUT)
    gif = [im.quantize(palette=palette, dither=Image.Dither.NONE) for im in images]
    # No `loop` argument: no NETSCAPE loop block, so viewers play the animation once and stop.
    gif[0].save(path, save_all=True, append_images=gif[1:], duration=[45] * (len(gif) - 1) + [60000], optimize=False)


def main(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for state in STATE_COLORS:
        render_icon(state).save(out_dir / f"icon_{state}.png")
    for score in range(0, 101):
        render_hero(score).save(out_dir / f"hero_{score}.png")
    render_hero(None).save(out_dir / "hero_unscanned.png")
    render_hero(0, trusted=True).save(out_dir / "hero_trusted.png")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "assets")
