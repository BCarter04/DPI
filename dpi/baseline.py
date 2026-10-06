"""Remember site names seen on this computer.

Copyright (c) 2023-2026 Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.

What it does now
    Saves each visible site name with the day it was first seen, in
    dpi-seen.json. The next demo or live run says which names are new.
    Names from the last 7 days stay in the file. This is not malware
    detection, and nothing is decrypted.

What it will do
    A later run can keep the same memory for longer. It still will not
    open the page.
"""

import json
import os
from datetime import date, datetime, timedelta


def _load(path):
    if not os.path.exists(path):
        return {}
    try:
        raw = json.load(open(path, encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(raw, list):
        return {name: date.today().isoformat() for name in raw}
    if isinstance(raw, dict):
        return {str(name): str(day) for name, day in raw.items()}
    return {}


def compare_names(names, path="dpi-seen.json"):
    """Return names not saved before, and remember today's names for 7 days."""
    previous = _load(path)
    fresh = sorted(set(names) - set(previous))
    today = date.today().isoformat()
    for name in names:
        previous.setdefault(name, today)
    cutoff = (date.today() - timedelta(days=7)).isoformat()
    kept = {name: day for name, day in previous.items() if day >= cutoff}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(kept, handle, indent=2)
    return fresh
