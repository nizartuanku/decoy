# Safety — read before planting traps

Decoy plants bait and runs decoy services that record who connects to them.
Used as intended, it is one of the safest, highest-signal tools in security.
Used carelessly, deception can become entrapment or a nuisance to others. This
page is the rule that keeps you clear.

## The one rule

**Plant tokens and honeypots only in systems you own or operate.**

A Decoy is bait placed in *your* environment to catch someone in *your*
environment. It is not for planting on third-party systems, shared hosting you
don't control, or anyone else's network.

## Decoy is passive

- A trap never reaches out, attacks back, or probes anything. It waits and
  records who came to it. It does not pursue.
- What it captures is incident evidence about an interaction with **your own**
  systems, stored on **your own** server. Nothing ever leaves your network —
  because nothing ever entered ours.
- Honeypots imitate generic infrastructure (a login panel, an SSH banner). Do
  not configure a honeypot to impersonate a specific third party's branded
  service in a way that could deceive that third party's users.

## Where honeypots may bind

A honeypot listens on a TCP port and records every connection. Run honeypots
where a scan or an intruder would land — an internal segment, a DMZ — on ports
that are free on that host. Do not bind a honeypot on a port a real service
needs. Any connection to a decoy port on a quiet segment is, by design,
suspicious — that's the point.

## DNS tokens and cloud credentials

- The **DNS token** needs a DNS zone delegated to Decoy's responder. Only
  delegate a zone you control.
- The **cloud-credential** trap generates an inert, fake AWS key. It grants
  nothing. Placing it in your own decoy files is fine; do not present fake
  credentials to third parties as if genuine.

## Your responsibility

By planting a trap you warrant that it sits in infrastructure you own or are
authorised to operate. Decoy records trips as evidence, but the responsibility
for lawful placement is yours. If you are unsure whether you may place a trap
somewhere, don't — ask first.
