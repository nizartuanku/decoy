# Decoy — Concepts

What this product is, what problem it solves, and why it works the way it does — written for
someone meeting the problem for the first time. The command reference is in the README; this
is the reasoning behind it.

*Hexward Labs · Nizar Tuanku — Cybersecurity. · last reviewed 6 September 2026*

---

## 1. The real problem
When an attacker gets into a network, the surprising part is not that they got in — it is how long they stay before anyone notices. The figure is measured in weeks, not minutes. In that time they read files, map the network, and set up their next move.
Why so long? Because the way we look for them is backwards.
Conventional detection watches all traffic and tries to separate the malicious from the ordinary. Imagine guarding a building by reviewing footage of everyone who walks past and guessing who means harm. The volume is enormous, and the malicious ones are deliberately trying to look ordinary. The result is predictable: thousands of alerts, most of them wrong, and a team that eventually stops reading them. This is called alert fatigue, and it kills more security programmes than attacks do.
## 2. Reversing the question
Deception reverses the direction. Instead of hunting a needle in a haystack, you plant a needle that screams.
You place something that looks valuable somewhere nobody has any reason to touch. A link called "backup keys". A spreadsheet called "salaries_2026". An idle database port. No employee has business with any of those — they have their own work and do not wander around looking for credentials.
So when one of them is touched, the conclusion has almost no alternative: someone is exploring your systems, and that someone is not an employee doing their job.
This is the difference that makes deception valuable. Ordinary detection tools have a poor signal-to-noise ratio because they must judge legitimate activity. Bait has no legitimate activity to judge at all — zero touches is its normal state. Every deviation from zero means something.
## 3. Five forms of bait, and when each one fires
Web/URL token. A link with an address nobody could guess. You plant it where only someone snooping would read it — inside an internal wiki, in a comment in a script, in a server's bookmark list. It fires the second it is fetched.
Document beacon. A .docx, .xlsx or .pdf file that, when opened, fetches a small image from your server. That fetch is the alarm — you get the IP of whoever opened it. Good for a share folder whose contents look sensitive. The honest limit: it only works in applications willing to fetch remote content — many, but not all.
Honeypot service. A port pretending to be a real SSH, RDP or database service, complete with a convincing greeting. It logs every connection. If an attacker tries to log into its fake admin panel, Decoy even captures the username and password they tried — which immediately tells you which credentials they believe are valid at your organisation.
DNS token. Some scanners look up names before touching anything at all. A DNS token fires at the resolution stage — before a single connection is made. This is what catches the most careful reconnaissance.
Cloud credential. A fake cloud access key placed where attackers habitually harvest — config files, shell history, code repositories. It fires when someone tries to use it.
The last two need setup outside Decoy (a delegated DNS zone; CloudTrail for AWS). That is stated openly, never quietly assumed.
## 4. Why "how many alerts" is a design question, not a detail
Good bait has one built-in weakness: a single attacker can touch it hundreds of times. An SSH brute-force tries thousands of passwords. A port scanner knocks repeatedly. If every knock became an alert, bait that was supposed to be high-signal would turn into a source of noise — exactly the disease we set out to avoid.
Decoy solves this by folding repetition. Touches on the same trap, from the same IP address, on the same thing, within a 15-minute window, become one incident with a count — not a hundred alerts.
Three things about this folding are worth understanding, because this is where the honesty lives:
First, only the notification is folded. Every individual touch is still stored as evidence, one by one, with first and last seen times. You lose no data for investigation; you simply are not woken a hundred times for one event.
Second, different source IPs are never folded together. A second attacker is a second event, however busy the first one is. Folding them would hide the single most important fact: that there are two people.
Third — and this is what separates an honest claim from a marketing one — the folding works on repetition, not on breadth. One scanner touching 30 different traps from 30 different addresses will still produce many alerts. And it should: 30 traps firing is a fundamentally different fact from 1 trap firing 30 times. The first means a broad intrusion; the second means one persistent person.
One detail that took us a second pass to get right: the immediate alert is sent on the FIRST touch, so by definition it cannot know how many follow. Since 6 September, when the 15-minute window closes Decoy sends one further short notification carrying the count — so twenty touches are exactly two messages, not one message that quietly understates what happened.
## 5. Where Decoy sits, and where it does not
Decoy is detection, not prevention. It does not keep anyone out; it tells you someone is already in. That distinction determines what you do with it: Decoy does not replace your firewall, your EDR, or your SIEM. It complements all of them with the one thing they cannot give you — a signal that is almost never wrong.
There is one limit to understand from the start: coverage equals placement. A trap planted somewhere an intruder will never pass will stay silent forever, and that silence proves nothing. Choosing where to plant is therefore the real work — not installing the tool.
And one rule that is not negotiable: plant only in systems you own or operate. Decoy is passive — it records who came, it never strikes back. But bait placed in someone else's systems stops being defence and starts being a legal problem.
## 6. Your data goes nowhere
Decoy runs as a single binary or container on your own infrastructure. Your traps, the touches they record, and the evidence never leave your network. There is no telemetry. Licence validation is offline cryptography — it never phones home, not even to check whether your key is still valid.
This is not an architectural preference. For a tool whose job is to record evidence of an intrusion, sending that evidence to somebody else's server is a contradiction.
## 7. Try it first
The free Apache-2.0 edition on GitHub is the whole engine, with no time limit.
```
curl -LO https://github.com/nizartuanku/decoy/releases/latest/download/decoy-free-0.1.0-linux-amd64.tar.gz
curl -LO https://github.com/nizartuanku/decoy/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS
tar xzf decoy-free-0.1.0-linux-amd64.tar.gz && ./decoy
```
Plant four traps, touch one of them yourself, and see what the alert looks like before you decide whether it belongs in your network. Pro and Team editions are on Whop.
Nizar Tuanku — Cybersecurity. · github.com/nizartuanku/decoy

## Terms used above

- A vulnerability scanner answers "is this exploitable?" Decoy answers the question that comes first: "is someone already inside?"
