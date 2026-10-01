"""Check that the demo still names the three sample sites."""

from dpi.analyze import analyze
from dpi.capture import build_demo_packets


def test_demo_names_the_sample_sites():
    summary = analyze(build_demo_packets(), "test")
    assert "example.com" in summary["names"]
    assert "www.example.com" in summary["names"]
    assert "cdn.example.net" in summary["names"]
    assert "YouTube" in summary["apps"]
    assert "Netflix" in summary["apps"]
    assert summary["flows"][0]["who"]
