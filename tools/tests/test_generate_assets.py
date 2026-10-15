import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import generate_assets as ga  # noqa: E402
from PIL import Image  # noqa: E402

RED = (211, 47, 47)


class GenerateAssetsTest(unittest.TestCase):
    def test_score_color_stops(self):
        self.assertEqual(ga.score_color(0), (46, 125, 107))
        self.assertEqual(ga.score_color(35), (201, 138, 44))
        self.assertEqual(ga.score_color(70), RED)
        self.assertEqual(ga.score_color(200), RED)
        self.assertEqual(ga.score_color(-5), (46, 125, 107))

    def test_gauge_alert_is_solid_red(self):
        img = ga.render_gauge(None).convert("RGBA")
        w, h = img.size
        px = [img.getpixel((x, h // 2)) for x in range(30, w - 30, 7)]
        self.assertTrue(all(p[3] > 0 for p in px))
        self.assertTrue(all(max(abs(p[i] - RED[i]) for i in range(3)) <= 6 for p in px))

    def test_gauge_filled_and_faded(self):
        img = ga.render_gauge(45).convert("RGBA")
        w, h = img.size
        filled = img.getpixel((int(w * 0.2), h // 2))
        faded = img.getpixel((int(w * 0.9), h // 2))
        self.assertLess(sum(filled[:3]), sum(faded[:3]))

    def test_main_writes_28_files_with_sizes(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            ga.main(out)
            files = sorted(p.name for p in out.glob("*.png"))
            self.assertEqual(len(files), 28)
            for name in ("gauge_alert.png", "gauge_90.png", "gauge_0.png"):
                self.assertIn(name, files)
            self.assertEqual(Image.open(out / "icon_safe.png").size, (128, 128))
            self.assertEqual(Image.open(out / "banner_malicious.png").size, (600, 140))
            self.assertEqual(Image.open(out / "gauge_50.png").size, (600, 70))

    def test_malicious_banner_is_mostly_red(self):
        img = ga.render_banner("malicious").convert("RGB")
        px = list(img.getdata())
        near = sum(1 for p in px if max(abs(p[i] - RED[i]) for i in range(3)) < 40)
        self.assertGreater(near / len(px), 0.6)


if __name__ == "__main__":
    unittest.main()
