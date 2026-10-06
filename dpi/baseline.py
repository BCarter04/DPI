"""Remember names from the last run on this computer.

Copyright (c) 2023-2026 Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.

What it does now
    Saves visible site names in dpi-seen.json. The next demo or live run
    says which names were not in that file. It does not call this malware.

What it will do
    A later run can keep several days. It still will not decrypt pages.
"""

import json
import os


def compare_names(names, path="dpi-seen.json"):
    """Return names that were not saved last time, then save the new list."""
    previous = set()
    if os.path.exists(path):
        try:
            previous = set(json.load(open(path, encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            previous = set()
    fresh = sorted(set(names) - previous)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(sorted(set(names) | previous), handle, indent=2)
    return fresh
