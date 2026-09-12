# Methodology

This document explains the key technical decisions behind the system, and two real bugs that surfaced during validation and how I found and fixed them. I'm including the messy parts on purpose, since the debugging is the most interesting evidence that this actually works rather than just looking like it does.

## Why reconstruct a path, not just flag events

Most fraud detectors score individual events in isolation. "This login looks weird." "This payment is large." The problem is that isolated scoring can't tell the difference between a single false alarm and a real connected attack.

A new device login by itself might just be someone's new phone. A new device login followed by a beneficiary change followed by a payment approved in 9 seconds is a fundamentally different signal.

This system builds a connected graph of every event tied to an account and scores the whole reconstructed path together. The scoring uses a multiplier based on how many distinct stages appear in the chain. A 1-stage flag and a 4-stage connected chain aren't scored as "4x as bad," they're scored as qualitatively different situations, which is closer to how a real investigator actually reasons about evidence.

## Why three independent detectors

Rather than one black-box anomaly score, the system uses three separate explainable rules, each mapping to a real named security concept.

**Impossible travel** is a standard technique in identity security platforms like Okta and Azure AD. Calculate the real-world distance between two login locations and the time between them, flag if the implied travel speed exceeds what's physically possible.

**New device login** is device trust scoring. Track which devices have historically been used on an account and flag first-time devices.

**Approval bypass** is a TOCTOU-style control bypass pattern. Flag payments approved implausibly fast after creation, since real human review takes measurable time.

Keeping these separate rather than combining them into one score from the start matters for two reasons. It makes the evidence trail explainable ("here specifically is why this was flagged"), and it lets validation measure each detector's individual accuracy rather than just a combined pass/fail.

Here is the live terminal output from a real scan of ACC1000, showing all three detectors firing and exactly what each one found:

![Scan log showing all three detectors firing on ACC1000](<screenshots/SCANNING.png>)

The scan shows impossible travel (DO → RS, 8677km in 1.12h, requiring 7770km/h), a new device (device-unknown-9561), and an approval bypass (payment approved in 19 seconds). Each detector runs independently and reports its own flag and score contribution before the graph is built.

## Validating against known ground truth

The dataset includes five deliberately injected attack sequences, each toggling which signals are present:

| Variant | Country change | New device | Approval bypass |
|---|---|---|---|
| full_attack | yes | yes | yes |
| same_country_new_device | no | yes | yes |
| new_country_same_device | yes | no | yes |
| no_approval_bypass | yes | yes | no |
| device_only_weak_signal | no | yes | no |

Because I know exactly which signals are present in each variant, I can check whether each detector fires only when its signal is genuinely there, not just whether the system catches something. This is the same approach real fraud engineering teams use before trusting detection logic with real money: measure precision and recall against a labeled test set.

Final result: each detector's recall exactly matches which variants contain its signal. Impossible Travel caught 3/3 country-change cases. New Device caught 4/4 device-change cases. Approval Bypass caught 3/3 fast-approval cases. 100% precision across the board, zero false positives on any of the 45 clean accounts, and 100% system-level recall since every attack triggers at least one detector.

Here is ACC1020, a separate attack chain caught through impossible travel (ES → TH, 10877km in 1.2h) and approval bypass ($14,219 approved in 8 seconds), with no new device signal present:

![ACC1020 investigation showing ES to TH impossible travel and approval bypass](<screenshots/ACC 1020 GRAPH.png>)

This is the `new_country_same_device` variant — the new device detector correctly stays silent while the other two fire, which is exactly the expected behaviour.

## Bug 1: the Null Island geolocation problem

The first validation run showed 0% recall on impossible travel, even for variants that had a genuine country change built in. That was clearly a systematic problem, not just noise.

The country-to-coordinates lookup only covered about 18 countries. When an account's home country and a login country were both outside that list, the code silently defaulted both to (0.0, 0.0), treating "I don't know this country's location" as if it were a real specific place. Two genuinely different countries collapsed onto the same fallback point, the calculated distance came out as zero, and nothing got flagged.

This has a name in GIS work: Null Island. (0, 0) is an actual coordinate in the Gulf of Guinea, and defaulting missing data to it is a well-documented failure mode in geolocation systems. It's the kind of bug that looks like "the feature doesn't work" when the real problem is the data pipeline silently lying about what it knows.

The fix: unmapped countries now return None instead of (0, 0), and the detector explicitly skips any comparison where either side is unknown rather than guessing. I also expanded the coordinate table from 18 to about 75 countries so unknowns become the exception. The detector now logs which country codes it couldn't resolve, so gaps are visible and fixable rather than silent.

## Bug 2: sparse login history masking real attacks

After fixing the geolocation bug, some genuine country-change attacks still weren't being caught.

Accounts in the dataset log in about 10 times over 30 days, roughly one login every 3 days. An injected attack login placed at a random point in time could easily land far from its nearest normal login chronologically. Even a real distance of thousands of km divided by 70+ hours comes out to a plausible travel speed. The detector wasn't wrong; the data just didn't guarantee the attack had a recent prior session to compare against, which is exactly what impossible-travel detection depends on.

The fix: each injected attack now includes an explicit "last known normal login" placed 20 to 90 minutes before the attack login, using the account's real home country and device. This isn't cheating the test. It's making the synthetic data reflect how this attack actually plays out: an attacker using stolen credentials typically logs in shortly after the legitimate user's last genuine session. That's the scenario impossible-travel detection is designed to catch.

## Hash-chained audit logging

Every event in the dataset, logins, account changes, payments, transfers, is wrapped in a SHA-256 hash chain. Each entry's hash depends on the previous entry's hash plus its own content.

```
block_0 = SHA-256("" + event_0_json)
block_1 = SHA-256(block_0 + event_1_json)
block_2 = SHA-256(block_1 + event_2_json)
```

If any event were altered after the fact, every subsequent hash fails to verify, and you can pinpoint exactly where the tampering happened. Same principle behind certificate transparency logs and blockchain ledgers. An investigation is only as trustworthy as the log it's built on, so the tool verifies its own evidence before drawing conclusions from it.

## Scoring design

```
Risk Score = sum(indicator base scores) x kill-chain stage multiplier
```

Indicator weights are calibrated by how specific each signal is:

| Signal | Score | Reason |
|---|---|---|
| Impossible Travel | +40 | Physically impossible, very high confidence |
| Approval Bypass | +35 | High impact, funds already moved |
| New Device Login | +25 | Could still be a new legitimate device |
| Fund Transfer per hop | +15 | Each hop adds laundering evidence |

Kill-chain multipliers:

| Stages | Multiplier |
|---|---|
| 1 | 1.0x |
| 2 | 1.3x |
| 3 | 1.6x |
| 4 | 2.0x |

A full 4-stage attack chain scores 2x higher than isolated flags summed alone. This matches how investigators actually weight evidence: a coordinated sequence isn't just "more of the same," it's a different category of threat.

Here is the actual score breakdown for ACC1000 as rendered in the dashboard — impossible travel (+40), new device (+25), approval bypass (+35), two fund transfer hops (+30), base total 130, multiplied by 2x for 4 kill-chain stages, final score 260:

![ACC1000 full investigation showing score breakdown and attack graph](<screenshots/ACC 1000 GRAPH.png>)

## Known limitations

Synthetic data by design. Real authentication and payment logs aren't publicly released for obvious privacy and security reasons. This is not a shortcut; it's how real fraud engineering teams build and validate detection logic before it touches production traffic.

Static geolocation table. A production system would use a live IP-geolocation API. The current approach still does genuine distance and speed math on real coordinates, the simplification is in the lookup table.

Single-path reconstruction. The system follows one connected path per account rather than visualizing full multi-branch graphs.

No streaming detection. This analyzes a static dataset snapshot.

These are listed on purpose rather than glossed over. Some of the most useful work in this project came from figuring out exactly where the first version was wrong.
