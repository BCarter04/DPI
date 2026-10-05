"""Turn the warnings into one plain sentence.

Copyright (c) 2023-2026 Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.

What it does now
    Reads the warnings already found and picks the most likely plain cause.
    It does not measure Wi-Fi signal, and it does not open the page.

What it will do
    A longer watch can compare this sentence with the last run.
"""


def why_it_looks_slow(summary):
    """One sentence a person can read without knowing packet terms."""
    metrics = summary.get("metrics") or {}
    repeats = metrics.get("repeated_sequences") or 0
    resets = metrics.get("resets") or 0
    names = summary.get("names") or []
    if repeats:
        return "Some packets were sent again. That often means a busy or weak link, not a broken website name."
    if resets:
        return "A connection was cut off. The site or app may have closed the talk, or the path dropped it."
    if any("failed" in item or "not found" in item for item in summary.get("alerts") or []):
        return "A name lookup failed. The computer may not be reaching the name service, or the name is wrong."
    if not names:
        return "No site name was visible. That can be normal. It does not by itself mean the network is slow."
    return "Nothing in this capture looks like a slow link. A short check can still miss a problem."
