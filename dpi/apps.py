"""Guess a common app from a visible name.

Copyright (c) 2023-2026 Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.

What it does now
    Matches a DNS name or TLS server name to a short list of well-known apps.
    YouTube can show up as googlevideo.com. Netflix can show up as nflxvideo.net.
    The match is the name only. The video, search, or page stays encrypted.

What it will do
    The list can grow when someone sends an idea. It will not start decrypting
    the stream to prove which title was playing.
"""

APP_MARKS = [
    ("YouTube", ("youtube", "googlevideo", "ytimg", "youtu.be")),
    ("Netflix", ("netflix", "nflxvideo", "nflximg")),
    ("Google", ("google", "gstatic", "googleapis", "gmail", "gvt1")),
    ("Facebook", ("facebook", "fbcdn", "fb.com")),
    ("Instagram", ("instagram", "cdninstagram")),
    ("WhatsApp", ("whatsapp",)),
    ("TikTok", ("tiktok", "musical.ly", "byteoversea")),
    ("Microsoft", ("microsoft", "office", "live.com", "windows")),
    ("Apple", ("apple", "icloud", "mzstatic")),
    ("Amazon", ("amazon", "amazonaws")),
    ("Spotify", ("spotify", "scdn.co")),
    ("Zoom", ("zoom.us",)),
    ("Discord", ("discord",)),
    ("X", ("twitter", "twimg", "x.com")),
    ("Reddit", ("reddit", "redd.it")),
]


def guess_app(name):
    """Return an app name, or None if the visible name is not in the list."""
    if not name:
        return None
    host = name.lower().rstrip(".")
    for app, marks in APP_MARKS:
        if any(mark in host for mark in marks):
            return app
    return None
