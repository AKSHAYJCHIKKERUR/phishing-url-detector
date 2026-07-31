# Phishing URL & Email Detector

A rule-based Python tool that analyzes URLs and email text to detect common
phishing red flags, and scores the risk from 0-100.

## Why I built this

Phishing is one of the most common attack vectors in cybersecurity, and email
security is a core part of the industry (companies like Barracuda Networks
build enterprise products around exactly this problem). I wanted a hands-on
way to learn the actual signals security tools look for, by building a
simplified version myself.

## How it works

The detector checks a URL or email body against known phishing patterns:

| Signal | Why it matters |
|---|---|
| No HTTPS | Legitimate sites almost always use encrypted connections |
| Raw IP address instead of domain | Attackers hide behind IPs to avoid domain registration/takedowns |
| URL shorteners (bit.ly, tinyurl, etc.) | Used to disguise the real destination |
| Excessive hyphens in domain | Common in fake domains like `paypal-secure-login.com` |
| Long URLs | Padding used to bury the real domain |
| Lookalike/typo domains | e.g. `paypa1.com` or `amaz0n.com` impersonating real brands |
| `@` symbol in URL | Browsers ignore everything before `@`, can hide the true destination |
| Urgency keywords | Phrases like "verify your account", "act now" exploit psychological pressure |
| **Live threat intelligence match** | Domain matches a feed of ~390,000 confirmed active phishing domains, verified by security researchers (see below) |

## Real-time threat intelligence

In addition to rule-based pattern checks, the detector now cross-references
every URL's domain against a **live, publicly maintained feed** of confirmed
phishing domains:

- **Source:** [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) -
  a project where security researchers continuously test and verify phishing
  domains using automated tooling, similar in concept to how commercial tools
  like Google Safe Browsing or VirusTotal work (but free and open, no API key needed)
- The feed is downloaded and cached locally (refreshed every 6 hours) so the
  tool isn't re-downloading ~390,000 domains on every single run
- If a domain is found in this feed, it's treated as **confirmed malicious**
  (risk score maxed at 100) - because it's not just a pattern match, it's been
  independently verified as an active phishing site

**Why this matters:** rule-based checks (hyphens, IP addresses, keywords) are
good at catching *new or unknown* phishing attempts that follow common
patterns, while the threat intelligence feed catches domains that have
*already been confirmed* by researchers - even if that specific domain
doesn't trip any of the pattern rules. Combining both gives broader coverage
than either approach alone, which is exactly how real commercial security
tools are architected (fast local rules + cloud-based threat intel lookups).

Each flag adds to a risk score. Score ≥ 60 = High Risk, 30-59 = Medium, below 30 = Low.

## Usage

```bash
python3 phishing_detector.py
```

Then paste a URL or email text at the prompt. Type `quit` to exit.

Example:
```
Enter URL or email text: http://192.168.1.5/paypal-login-secure
==================================================
Risk Score: 40/100
Verdict: MEDIUM RISK - Suspicious, review carefully
Reasons flagged:
  - URL does not use HTTPS
  - Uses a raw IP address instead of a domain name
==================================================
```

## Testing accuracy

Run the included test set of 16 known phishing-style and legitimate URLs:

```bash
python3 test_detector.py
```

Current accuracy: **87.5% (14/16)**

## Limitations & what I'd add next

This is intentionally **rule-based**, not machine learning, so I could focus
on understanding the actual signals first. Known limitations:

- Doesn't catch clever character substitutions in all cases (e.g. `0` for `o`)
  without a proper Levenshtein-distance / lookalike-domain library
- No domain age / WHOIS lookup (freshly registered domains are a strong
  phishing signal)
- Could be extended with a trained ML classifier using a labeled phishing
  dataset (e.g. PhishTank) for higher accuracy at scale

## Tech stack

Python 3, standard library only (`re`, `urllib.parse`) — no external
dependencies, so it runs anywhere.
