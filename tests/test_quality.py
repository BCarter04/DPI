"""Quality check: demo and live share the same report lines."""
from dpi.capture import build_demo_packets
from dpi.analyze import analyze
from dpi.report import top_guess, write_html

def test_demo_report_has_the_shared_lines():
    summary = analyze(build_demo_packets(), 'demo')
    assert summary.get('score') == 100
    assert summary.get('dns_health') == 'Good'
    assert 'BBC' in summary.get('apps')
    assert top_guess(summary).startswith('Encrypted web')
    assert len(summary.get('devices') or []) >= 1
    path = '/tmp/dpi-quality.html'
    write_html(path, summary)
    text = open(path, encoding='utf-8').read()
    for item in ['Top guess', 'Limits of this reading', 'Likely router', 'BBC']:
        assert item in text
