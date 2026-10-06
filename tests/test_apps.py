"""Checks for the app name list. Demo and live use the same list."""

from dpi.apps import guess_app


def test_known_names():
    assert guess_app("rr3.googlevideo.com")[0] == "YouTube"
    assert guess_app("ipv4-c002.nflxvideo.net")[0] == "Netflix"
    assert guess_app("www.bbc.co.uk")[0] == "BBC"
    assert guess_app("not-a-known-site.example")[0] is None
