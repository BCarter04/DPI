"""Say if a site name was reached in this capture.

Copyright (c) 2023-2026 Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.

What it does now
    Looks at names already found. It does not open the site, and it does
    not decrypt the page. Demo and live use the same check.

What it will do
    A later check can say the lookup failed before the handshake. It still
    will not open the page.
"""


def reach_note(summary, wanted):
    """Plain sentence for one site name."""
    needle = (wanted or "").lower().strip()
    if not needle:
        return ""
    names = [name.lower() for name in summary.get("names") or []]
    seen = any(needle in name for name in names)
    failed = any(needle in item.lower() for item in summary.get("alerts") or [])
    if seen and not failed:
        return f"Could {wanted} be reached? The name was visible in this capture. The page itself stays hidden."
    if failed:
        return f"Could {wanted} be reached? A lookup for that name failed in this capture."
    return f"Could {wanted} be reached? That name was not in this capture. A short check can miss it."
