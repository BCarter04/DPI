"""Checks the 7-day name memory. Demo and live use the same file format."""

import os

from dpi.baseline import compare_names


def test_new_name_once(tmp_path=None):
    path = "/tmp/dpi-memory-test-" + str(os.getpid()) + ".json"
    if os.path.exists(path):
        os.remove(path)
    first = compare_names(["bbc.co.uk"], path)
    second = compare_names(["bbc.co.uk", "gov.uk"], path)
    os.remove(path)
    assert first == ["bbc.co.uk"]
    assert second == ["gov.uk"]
