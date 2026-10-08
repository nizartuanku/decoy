# Sample run

This is real Decoy output, not a mockup. Three traps armed on the free tier,
tripped for real in a local lab, exported exactly as the API returned them —
nothing in [`sample-findings.json`](sample-findings.json) or
[`sample-trips.json`](sample-trips.json) was hand-edited.

**Source:** a lab instance of Decoy 0.1.2, free edition, run on an isolated
host with no real users. The "intruder" touches below were made by the person
documenting this sample, from `127.0.0.1` — there was no real attacker. No
customer deployment, trap, or trip is reproduced here.

## What was armed

| Label | Kind | Detail |
|---|---|---|
| `backup-keys-link` | Web/URL token | — |
| `salaries-export-2026` | Web/URL token | — |
| `decommissioned-admin-ssh` | Honeypot | fake SSH service, port 12222 |

Free tier allows 3 tokens and 1 honeypot — this sample uses the edition at its
own limit: `max_targets: 4` (3 tokens + 1 honeypot), confirmed by
`GET /api/summary` in `sample-findings.json`'s companion run.

## What tripped, and what Decoy reported

| Trap | Touches | Finding severity | Folded? |
|---|---|---|---|
| `decommissioned-admin-ssh` | 1 (raw TCP connect + banner probe) | **critical** | — |
| `backup-keys-link` | 2 (same source, 1 second apart) | **high** | yes — one finding, `count: 2` |
| `salaries-export-2026` | 0 | — (still armed, `info`) | — |

```
critical  DECOY TRIPPED: decommissioned-admin-ssh touched by 127.0.0.1
high      DECOY TRIPPED: backup-keys-link touched 2 times by 127.0.0.1
```

The two touches on `backup-keys-link` landed inside the same 15-minute digest
window (`digest_window: "15m0s"`, configurable), so they fold into **one**
finding with `count: 2` and one notification — not two separate alerts. A
touch that arrives after the window closes starts a new finding instead. This
is the behavior documented in the main README under "Alerts with the
attacker's fingerprints."

Honeypot findings are reported at **critical**, token findings at **high** —
a raw connection to a fake SSH/RDP/admin port signals a more active probe than
a single link fetch, so the severities are not identical.

## Reading the evidence honestly

Every tripped finding carries the full evidence block: source IP, first/last
seen, the digest window, and kind-specific detail (`first_bytes` for the
honeypot — the first bytes the connecting client sent; `path`/`user_agent`
for the web token). Nothing is summarized away. See `evidence` in
`sample-findings.json`.

The three `info` findings in the same export (`trap.armed`) are not
incidents — they are Decoy confirming each trap is live and waiting. A fresh
deployment always starts at `info`; only a touch promotes it.

## What this sample does not show

- **Document beacons, DNS tokens, cloud-credential traps** — Pro/Team-tier
  trap kinds (DNS and cloud-credential) and the `.docx`/`.xlsx`/`.pdf` beacon,
  which phones home on open rather than on fetch. Not exercised here because
  this sample stays inside the free edition's caps.
- **A real intruder.** The touches above were made deliberately, from the
  same host, to produce real API output for this document. Decoy cannot tell
  a documentation exercise from a real probe, and does not try to — that is
  the point of the design: every touch is treated as real, because a real
  trap is never touched by accident.
- **AI Assist narration.** This export was taken with the AI Assist sidecar
  off, to keep the sample focused on the engine's own findings (which are the
  only source of severity and evidence — AI only narrates them). A live,
  end-to-end AI Assist run against a Decoy finding, sidecar up and sidecar
  down, is documented in `docs/CONCEPTS.md` and verified in this product's
  release QC sweeps.

## Reproducing this

```bash
git clone https://github.com/nizartuanku/decoy && cd decoy
go build ./cmd/decoy && ./decoy -listen 127.0.0.1:8424

curl -s -X POST http://127.0.0.1:8424/api/decoy/deployments \
  -H 'Content-Type: application/json' \
  -d '{"kind":"web_token","label":"backup-keys-link"}'
# fetch the returned "url" once or twice to trip it

curl -s -X POST http://127.0.0.1:8424/api/decoy/deployments \
  -H 'Content-Type: application/json' \
  -d '{"kind":"honeypot","label":"decommissioned-admin-ssh","service":"ssh","port":12222}'
# connect to 127.0.0.1:12222 with nc or ssh to trip it

curl -s http://127.0.0.1:8424/api/findings | jq .
```

## Provenance

All labels and the source address are synthetic, made up for this document.
The JSON exports are the unedited output of a lab run on 8 Oct 2026 against
Decoy 0.1.2 (free edition), captured for this documentation and for no other
purpose.
