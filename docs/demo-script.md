# Demo script

Send these four emails to the Gmail account the add-on is installed on, open each, and check the card.
Start the backend + ngrok first (see README), and `clasp push` the latest code.

| # | Email | What to expect |
|---|---|---|
| 1 | **Safe** — from a colleague, plain text, no links: "Lunch tomorrow?" | Green hero "ALL CLEAR" with a low score; nothing else but "View details" |
| 2 | **Suspicious** — from `billing@examp1e-store.com`, one link whose text says `example.com` but href is `http://bit.ly/x1` | Amber hero with the score; one plain-language finding about the shortener/mismatch |
| 3 | **Malicious** — display name "PayPal Security", from `security@paypa1-support.com`, "URGENT: verify your account now", link text `https://paypal.com/verify` -> `http://paypa1-support.com/verify`, attachment `invoice.pdf.exe` | Red banner "DANGER — LIKELY MALICIOUS", bold red "What to do", filled red buttons incl. "Report as phishing"; solid-red gauge if the score is above 90 |
| 4 | **Not scanned** — stop the backend (or ngrok), then open any email | Grey hero "NOT SCANNED" / "Use your usual caution" (never reads as safe) |

Trusted senders: tap **Trust sender** on email #2 -> the card becomes the green "TRUSTED SENDER" card with risk 0.
Then add email #3's sender to the list (⋮ -> Trusted senders) and reopen #3: it must break through with the red card and
"this sender is on your trusted list, but this email looks dangerous" (a forged trusted address is not a free pass).
Open "View details" on #3 and #1 to show grouped findings and the "What we checked" list.
