"""Checks the report stays safe. Demo and live use the same writer."""
from dpi.analyze import analyze
from dpi.report import write_html

def test_empty_report():
    summary = analyze([], "empty")
    path = "/tmp/dpi-empty-report.html"
    write_html(path, summary)
    text = open(path, encoding="utf-8").read()
    assert "No packets were read." in text

def test_name_is_escaped():
    summary = analyze([], "empty")
    summary["flows"] = [{"who": "odd<name>", "category": "Other", "server_name": None, "dns_name": None, "health": "ok", "packets": 1, "bytes": 1, "duration": None, "handshake_ms": None, "reply_gap_ms": None}]
    path = "/tmp/dpi-escape-report.html"
    write_html(path, summary)
    text = open(path, encoding="utf-8").read()
    escaped = "&" + "lt;name&" + "gt;"
    assert escaped in text
