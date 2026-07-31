"""
Threat Intelligence Module
---------------------------
Connects to a live, publicly maintained feed of confirmed phishing domains
(Phishing.Database project - security researchers who continuously test and
verify phishing domains, similar in concept to what commercial tools like
Google Safe Browsing or VirusTotal do, but free and open).

Source: https://github.com/mitchellkrogza/Phishing.Database

This gives the detector a REAL threat intelligence signal, not just pattern
matching - if a domain is in this list, it has been independently confirmed
as an active phishing site by security researchers.

The feed is cached locally for a few hours so we're not re-downloading
~390,000 domains on every single run.
"""

import os
import time
import urllib.request

FEED_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
CACHE_FILE = os.path.join(os.path.dirname(__file__), ".phishing_feed_cache.txt")
CACHE_MAX_AGE_SECONDS = 6 * 60 * 60  # refresh cache every 6 hours

# In-memory cache so we only load the file into a set once per program run
_domain_set = None


def _cache_is_fresh() -> bool:
    if not os.path.exists(CACHE_FILE):
        return False
    age = time.time() - os.path.getmtime(CACHE_FILE)
    return age < CACHE_MAX_AGE_SECONDS


def _download_feed() -> bool:
    """Download the latest phishing domain feed. Returns True on success."""
    try:
        req = urllib.request.Request(
            FEED_URL, headers={"User-Agent": "phishing-detector-project"}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            data = response.read().decode("utf-8", errors="ignore")
        with open(CACHE_FILE, "w") as f:
            f.write(data)
        return True
    except Exception as e:
        print(f"[threat_intel] Could not fetch live feed: {e}")
        return False


def load_known_phishing_domains() -> set:
    """
    Return a set of known phishing domains, using the local cache if it's
    still fresh, or downloading a new copy if it's stale/missing.
    Falls back to whatever cache exists (even if stale) if the network
    request fails - fails safe rather than crashing the whole tool.
    """
    global _domain_set

    if _domain_set is not None:
        return _domain_set  # already loaded this run

    if not _cache_is_fresh():
        downloaded = _download_feed()
        if not downloaded and not os.path.exists(CACHE_FILE):
            # No cache at all and download failed - operate without threat intel
            _domain_set = set()
            return _domain_set

    with open(CACHE_FILE, "r") as f:
        _domain_set = set(line.strip().lower() for line in f if line.strip())

    return _domain_set


def check_domain(hostname: str) -> dict:
    """
    Check a hostname against the live threat intelligence feed.
    Returns dict with 'is_known_malicious' bool and a 'source' note.
    """
    if not hostname:
        return {"is_known_malicious": False, "checked": False}

    domains = load_known_phishing_domains()
    if not domains:
        return {"is_known_malicious": False, "checked": False}

    hostname = hostname.lower()
    is_match = hostname in domains

    return {"is_known_malicious": is_match, "checked": True}
