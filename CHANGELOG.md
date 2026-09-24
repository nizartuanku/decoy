# Changelog

## Unreleased

- **AI Assist (optional): an ✨ Explain button on every finding.** When Decoy is started
  with `-ai-assist-url`, a local [hexward-ai](https://github.com/nizartuanku/hexward-ai) sidecar
  explains a finding in plain language and lists what to verify. The engine remains the only
  source of findings and severity. Only one sanitised finding is sent (secret-like evidence keys
  are dropped). Any AI failure shows a quiet note and changes nothing. Free edition: a sidecar on
  the same host. Pro/Team: also a dedicated AI host or your own endpoint
  (`-ai-assist-key-file`). English or Bahasa Indonesia (`-ai-assist-lang`). New endpoints
  `GET /api/ai` and `POST /api/findings/explain`, covered by tests for: AI off, bad config,
  sanitising, tier gating, sidecar down, and bad requests.
- **`scripts/first-run.sh` — one command from a clean machine to a working dashboard.** It resolves the latest release at run time rather than pinning a tag, verifies the download against `SHA256SUMS` with no `--ignore-missing`, extracts, starts the binary and polls the dashboard until it answers. If the port is already taken it says so instead of letting the binary exit a second later and read like a broken product (`FIRST_RUN_PORT` overrides). When the unauthenticated GitHub API budget of 60 calls per hour is spent, the script now names the rate limit and when it resets, instead of reporting "cannot reach".
- **The CONCEPTS install block points at an archive that exists.** `docs/CONCEPTS.md` still named the 0.1.0 asset after 0.1.1 was published, so the documented `curl` fetched a URL that had moved on. It names the 0.1.1 asset now.

## 0.1.1 — 2026-09-07

### A burst of touches is one alert, and the alert says how many

A finding's fingerprint included the trip id, which is unique per touch. One
scanner sweeping one trap therefore produced one finding and one notification
per request — hundreds a minute, which is exactly the flood the README promised
would not happen.

Touches are now folded by **trap + source IP + what was touched** inside a
wall-clock window (15 minutes by default, configurable through `DigestWindow`).
The window is bucketed with `time.Truncate` rather than counted from the first
touch, so a real-time sink and a polling collector derive the same identity
without sharing any state. A different source IP still alerts on its own, and a
touch after the window closes opens a new alert.

The first notification is sent immediately and unchanged — a canary is worth
nothing if it is slow. When the window closes and more than one touch landed in
it, a second short notification reports the count: *"… touched N times by <ip>
in the last 15 min"*. Previously only the dashboard knew there had been twenty;
the alert itself never said so.

Every trip is still stored as evidence, with a count and first/last seen. Only
the notifications are folded, never the record.

### Verification identifiers renamed to Hexward

The HTTP header, DNS TXT label and well-known file used to prove domain
ownership are now `X-Hexward-Token`, `_hexward-verify.<domain>` and
`/.well-known/hexward-verify.txt`. Verification accepts either the old or the
new name and the webhook sends both headers, so a challenge set up before the
rename never returns to pending and an existing receiver keeps working. The old
names are removed on **1 March 2027**.

### Where the paid editions are, from inside the product

The licence panel, the footer, and the message you get when a free-edition limit
is reached now point at the product page. No banner, no modal, no countdown.

### Documentation and packaging

- `docs/CONCEPTS.md`: what a canary token actually proves, and what it does not.
- The edition table now says what the code does: free alert channels are webhook
  **and** syslog.
- The licence file ships the full Apache-2.0 text as `LICENSE.txt`, replacing a
  stub that collided with the `license` package directory on case-insensitive
  filesystems.
- The container image owns `/data` as the application user, so a mounted volume
  is writable without running as root.

## 0.1.0 — 2026-08-21

First public release.
