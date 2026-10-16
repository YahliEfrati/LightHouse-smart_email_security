import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import generate_assets as ga  # noqa: E402
from PIL import Image  # noqa: E402

RED = (211, 47, 47)


def close(a, b, tol=8):
    return max(abs(a[i] - b[i]) for i in range(3)) <= tol


class GenerateAssetsTest(unittest.TestCase):
    def test_score_color_stops(self):
        self.assertEqual(ga.score_color(0), (46, 125, 107))
        self.assertEqual(ga.score_color(35), (201, 138, 44))
        self.assertEqual(ga.score_color(70), RED)
        self.assertEqual(ga.score_color(200), RED)
        self.assertEqual(ga.score_color(-5), (46, 125, 107))

    def test_state_thresholds_match_backend(self):
        self.assertEqual([ga.state_for_score(s) for s in (0, 34, 35, 69, 70, 100)],
                         ["safe", "safe", "suspicious", "suspicious", "malicious", "malicious"])

    def test_hero_size_and_background_follow_state(self):
        for score, color in ((10, ga.STATE_COLORS["safe"]), (50, ga.STATE_COLORS["suspicious"]),
                             (80, ga.STATE_COLORS["malicious"])):
            img = ga.render_hero(score).convert("RGB")
            self.assertEqual(img.size, (600, 230))
            self.assertTrue(close(img.getpixel((580, 10)), color), score)
        self.assertTrue(close(ga.render_hero(None).convert("RGB").getpixel((580, 10)), ga.STATE_COLORS["unscanned"]))

    def test_gauge_filled_then_faded(self):
        img = ga.render_hero(45).convert("RGB")
        filled, faded = img.getpixel((100, 186)), img.getpixel((540, 186))
        self.assertLess(sum(filled), sum(faded))

    def test_above_90_gauge_is_solid_red(self):
        img = ga.render_hero(95).convert("RGB")
        for x in (60, 200, 340, 420):
            self.assertTrue(close(img.getpixel((x, 186)), RED), x)
        mid = ga.render_hero(90).convert("RGB")
        self.assertFalse(close(mid.getpixel((200, 186)), RED))

    def test_main_writes_all_files(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            ga.main(out)
            files = {p.name for p in out.glob("*.png")}
            self.assertEqual(len(files), 4 + 101 + 1)
            for name in ("hero_0.png", "hero_100.png", "hero_unscanned.png", "icon_safe.png"):
                self.assertIn(name, files)
            with Image.open(out / "icon_safe.png") as im:
                self.assertEqual(im.size, (128, 128))


if __name__ == "__main__":
    unittest.main()
