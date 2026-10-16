# Result card redesign — design spec

Date: 2026-10-16 · Status: draft, pending review

## Goal
Make the add-on's verdict unmistakable at a glance and easy to explain in an interview.
A dangerous email must *shout*; a safe one must stay quiet, so red keeps its meaning (no alarm fatigue).
Priorities: (1) a clear product/design story for the demo, (2) a better user experience.

## Constraints
- Gmail card UI (CardService): no custom CSS, no card background color. Only an Image widget can paint a full-width color block.
- Least privilege is kept: scopes stay `gmail.addons.execute`, `gmail.addons.current.message.readonly`, `script.external_request`. No `gmail.modify` (so no labeling/moving mail; documented trade-off).
- Backend verdicts today: score >= 70 Malicious, >= 35 Suspicious, else Safe (`analyzer.py`, `VERDICT_THRESHOLDS`).

## Voice
Hybrid: headlines and findings are plain and direct; the lighthouse personality lives in subtitles and explanatory copy.

## Identity & assets
All static, committed to the repo, generated reproducibly by `tools/generate_assets.py`, and loaded from `raw.githubusercontent.com` (no third-party dependency; `logoUrl` in `appsscript.json` points to the same icon).
- **Icon (option A: lighthouse on a dark-blue tile)**, 4 states by beam color: safe `#2E7D6B`, suspicious `#C98A2C`, malicious `#D32F2F`, unscanned `#8A949B`.
- **Banners (full width)**: 4 states. The malicious banner is large, red, with a warning sign and "DANGER — LIKELY MALICIOUS".
- **Risk gauge (horizontal)**: 20 images: steps of 5 from 0 to 90, plus one solid-red "alert" image for scores above 90 (rounding 91 to 90 would otherwise break the rule).

## Intensity ladder
| State | Presentation |
|---|---|
| Safe | Short, quiet card; thin green banner; one line |
| Suspicious | Amber banner; the single most important finding highlighted; "check before you act" |
| Malicious | Large red banner first; red filled primary button ("Report this email"); bold red "What to do" line; header in caps |
| Not scanned | Grey icon; "This email wasn't scanned — use your usual caution." (never implies safety) |

## Risk gauge
- Gradient green (0) → amber (35) → red (70), aligned to the backend verdict thresholds.
- Filled portion bright, remainder faded to show the scale.
- Score > 90: the **entire bar, number and banner turn solid red** (no gradient, no doubt).
- Image uses the score rounded to the nearest 5; the exact score is also shown as text ("73 / 100"). Score is labeled an estimate, not a certainty.

## Card content
1. Banner for the state.
2. Top finding in one sentence, with the evidence ("link says paypal.com but goes to paypa1-support.com") — the highest-weight reasoning item.
3. Gauge + exact score.
4. "What to do" line.
5. Buttons: View details, Trust this sender, "I think this is a mistake" (+ Report this email when malicious).

Details card: findings grouped by category, human wording first, technical evidence in small text below; final "What we checked" section listing checks that ran and passed, so a safe email is not an empty screen.

## Behavior changes
- Backend unreachable -> "Not scanned" card (grey), not "The beacon is resting".
- Trusted sender -> still scanned; show the trusted card unless a finding fires (spoofed trusted address would otherwise bypass the scan entirely).

## Out of scope / known gaps (for README "with more time")
- `headers` are sent empty, so SPF/DKIM/DMARC rules never fire; fixing needs header access (extra scope or alternative).
- No URL reputation (deliberate privacy choice).
- No mailbox-level actions (needs `gmail.modify`).

## Testing
- Unit tests for score -> gauge image selection (boundaries 0, 4/5, 90, 91, 100) and verdict -> banner/icon mapping.
- Manual demo script with 4 emails: safe, suspicious, malicious, backend-down.

## Revision 2 (after first live test in Gmail)
Findings from the live screenshots, and what changed:
- The sidebar title was clipped ("Lighthouse - Smar…"): `gmail.name` in the manifest is now just **"Lighthouse"**.
- The lighthouse appeared twice (card header + banner) and the headline twice: the result card now has **no card header**.
- The card was noisy. The first screen now holds only: **hero image**, one plain-language finding, a "What to do" line (malicious only) and one button. "Trust this sender" and "I think this is a mistake" moved to the card's overflow menu; the sender name and technical details were removed from the first screen (details stay in the details card).
- **Hero image replaces banner + gauge images**: one pre-rendered 600x230 PNG per integer score 0-100 (`hero_<score>.png`) with the verdict color, big score and gradient gauge, plus `hero_unscanned.png`. Above 90 the gauge turns solid red. Colors follow the backend thresholds (35/70); the generator mirrors them in `state_for_score`.
- Malicious copy changed from "LIKELY PHISHING" to **"LIKELY MALICIOUS"** (the checks cover attachments and obfuscation, not just phishing); the button is "Report this email".
