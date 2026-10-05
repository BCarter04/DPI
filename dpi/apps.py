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
    ("BBC", ("bbc.co.uk", "bbci.co.uk", "bbc.com")),
    ("ITV", ("itv.com", "itvstatic")),
    ("Channel 4", ("channel4.com", "c4assets")),
    ("Sky", ("sky.com", "skyassets")),
    ("Now TV", ("nowtv.com",)),
    ("Disney+", ("disneyplus", "disney+", "bamgrid")),
    ("Prime Video", ("primevideo", "aiv-cdn")),
    ("Spotify", ("spotify", "scdn.co")),
    ("Apple Music", ("music.apple", "itunes")),
    ("Deezer", ("deezer",)),
    ("BBC Sounds", ("sounds.bbc",)),
    ("WhatsApp", ("whatsapp",)),
    ("Instagram", ("instagram", "cdninstagram")),
    ("Facebook", ("facebook", "fbcdn", "fb.com")),
    ("TikTok", ("tiktok", "musical.ly", "byteoversea")),
    ("Snapchat", ("snapchat", "snap.com")),
    ("X", ("twitter", "twimg", "x.com")),
    ("Reddit", ("reddit", "redd.it")),
    ("Discord", ("discord",)),
    ("Zoom", ("zoom.us",)),
    ("Microsoft Teams", ("teams.microsoft", "teams.cdn")),
    ("Outlook", ("outlook", "office365")),
    ("Gmail", ("gmail", "mail.google")),
    ("Google", ("google", "gstatic", "googleapis", "gvt1")),
    ("Microsoft", ("microsoft", "office.com", "live.com", "windows")),
    ("Apple", ("apple.com", "icloud", "mzstatic")),
    ("Amazon", ("amazon", "amazonaws")),
    ("eBay", ("ebay",)),
    ("Tesco", ("tesco.com",)),
    ("Sainsbury's", ("sainsburys.co.uk",)),
    ("ASDA", ("asda.com",)),
    ("Argos", ("argos.co.uk",)),
    ("John Lewis", ("johnlewis.com",)),
    ("Rightmove", ("rightmove.co.uk",)),
    ("Zoopla", ("zoopla.co.uk",)),
    ("Deliveroo", ("deliveroo",)),
    ("Uber", ("uber.com", "ubereats")),
    ("Just Eat", ("just-eat", "justeat")),
    ("Trainline", ("thetrainline",)),
    ("National Rail", ("nationalrail",)),
    ("NHS", ("nhs.uk",)),
    ("GOV.UK", ("gov.uk", "service.gov")),
    ("HMRC", ("hmrc.gov",)),
    ("Lloyds", ("lloydsbank",)),
    ("Barclays", ("barclays",)),
    ("HSBC", ("hsbc",)),
    ("NatWest", ("natwest",)),
    ("Monzo", ("monzo",)),
    ("Revolut", ("revolut",)),
    ("PayPal", ("paypal",)),
    ("Steam", ("steampowered", "steamcommunity")),
    ("Twitch", ("twitch.tv",)),
    ("Roblox", ("roblox",)),
    ("Wikipedia", ("wikipedia", "wikimedia")),
    ("ChatGPT", ("openai.com", "chatgpt")),
    ("LinkedIn", ("linkedin",)),
    ("Pinterest", ("pinterest",)),
]


def guess_app(name):
    """Return (app, confidence) from a visible name, or (None, None).

    A name match is high confidence. It is still not the video title.
    """
    if not name:
        return None, None
    host = name.lower().rstrip(".")
    for app, marks in APP_MARKS:
        if any(mark in host for mark in marks):
            return app, "high, because the site name matched"
    return None, None
