"""
Turn a DPI analysis into a single HTML page a beginner can read.

The page explains what was seen, in normal words, and does not
require any extra libraries.
"""

from html import escape


def _bar_rows(pairs):
    """Build simple CSS bar rows from (label, count) pairs."""
    if not pairs:
        return "<p>Nothing to show.</p>"
    top = max(count for _, count in pairs) or 1
    rows = []
    for label, count in pairs:
        width = max(4, int(100 * count / top))
        rows.append(
            "<div class='row'>"
            f"<div class='label'>{escape(str(label))}</div>"
            f"<div class='track'><div class='fill' style='width:{width}%'></div></div>"
            f"<div class='count'>{count}</div>"
            "</div>"
        )
    return "\n".join(rows)


def write_html(path, summary):
    """Write the report. `summary` is the dict returned by analyze()."""
    categories = summary["categories"]
    flows = summary["flows"]
    metrics = summary["metrics"]
    notes = summary["notes"]

    cat_rows = _bar_rows(sorted(categories.items(), key=lambda item: -item[1]))
    flow_rows = []
    for flow in flows[:12]:
        sni = flow.get("server_name") or "—"
        flow_rows.append(
            "<tr>"
            f"<td>{escape(flow['who'])}</td>"
            f"<td>{escape(flow['category'])}</td>"
            f"<td>{escape(sni)}</td>"
            f"<td>{flow['packets']}</td>"
            f"<td>{flow['bytes']}</td>"
            "</tr>"
        )
    if not flow_rows:
        flow_rows.append("<tr><td colspan='5'>No conversations found.</td></tr>")

    note_items = "".join(f"<li>{escape(note)}</li>" for note in notes)
    proto_bits = ", ".join(
        f"{name}: {count}" for name, count in metrics["protocol_names"].items()
    ) or "none"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DPI demo report</title>
  <style>
    :root {{
      --ink: #1c2430;
      --muted: #5c6b7a;
      --line: #e4e9ef;
      --paper: #f6f8fb;
      --card: #ffffff;
      --accent: #1f6feb;
    }}
    body {{
      margin: 0;
      font-family: Georgia, "Iowan Old Style", serif;
      color: var(--ink);
      background: var(--paper);
    }}
    main {{ max-width: 880px; margin: 0 auto; padding: 32px 20px 64px; }}
    h1 {{ font-size: 2rem; margin-bottom: 0.2rem; }}
    h2 {{ font-size: 1.25rem; margin-top: 2rem; }}
    p, li {{ line-height: 1.5; }}
    .lede {{ color: var(--muted); font-size: 1.05rem; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }}
    .card {{ background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 14px 16px; }}
    .card b {{ display: block; font-size: 1.4rem; font-family: ui-sans-serif, sans-serif; }}
    .card span {{ color: var(--muted); font-size: 0.9rem; }}
    .panel {{ background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 16px; }}
    .row {{ display: grid; grid-template-columns: 180px 1fr 48px; gap: 10px; align-items: center; margin: 8px 0; font-family: ui-sans-serif, sans-serif; font-size: 0.92rem; }}
    .track {{ background: #eef2f6; border-radius: 999px; height: 10px; }}
    .fill {{ background: var(--accent); height: 10px; border-radius: 999px; }}
    table {{ width: 100%; border-collapse: collapse; font-family: ui-sans-serif, sans-serif; font-size: 0.92rem; }}
    th, td {{ text-align: left; padding: 8px 6px; border-bottom: 1px solid var(--line); vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; }}
    code {{ font-family: ui-monospace, monospace; font-size: 0.9em; }}
  </style>
</head>
<body>
  <main>
    <h1>DPI look at this traffic</h1>
    <p class="lede">This page is a plain-language reading of the packets. Nothing was decrypted. Encrypted payloads stay encrypted. We only use what a network can already see: addresses, ports, sizes, timing, and the server name if the TLS handshake still shows it.</p>

    <div class="cards">
      <div class="card"><b>{metrics['packet_count']}</b><span>packets read</span></div>
      <div class="card"><b>{metrics['duration_seconds']}s</b><span>time span</span></div>
      <div class="card"><b>{metrics['packets_per_second']}</b><span>packets per second</span></div>
      <div class="card"><b>{metrics['total_payload_bytes']}</b><span>payload bytes</span></div>
    </div>

    <h2>What the traffic looks like</h2>
    <div class="panel">
      {cat_rows}
    </div>
    <p>Transport mix: {escape(proto_bits)}. Source: {escape(summary['source'])}.</p>

    <h2>Conversations</h2>
    <p>A conversation is both directions between the same two computers and ports. The name in the server column is the TLS Server Name Indication, when the handshake included one. It is not the contents of the page.</p>
    <div class="panel">
      <table>
        <thead><tr><th>Who talked</th><th>Best guess</th><th>Server name</th><th>Packets</th><th>Bytes</th></tr></thead>
        <tbody>
          {''.join(flow_rows)}
        </tbody>
      </table>
    </div>

    <h2>How to read this</h2>
    <ul>
      {note_items}
    </ul>
    <p>Ports are only a hint. An app can use port 443 and still not be a browser. The useful next step for encrypted traffic is to group packets into conversations and compare size and timing, which this report already starts.</p>
  </main>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(html)
