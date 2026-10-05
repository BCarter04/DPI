"""Write the one-page report.

Copyright (c) 2023-2026 Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.

What it does now
    Turns the analysis into report.html: counts, what stands out, busiest
    addresses, and conversations. No extra library is required.

What it will do
    Later pages can add charts. They should keep the same plain-language
    sentences so a new reader still understands the result.
"""

from html import escape


def _bars(pairs):
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
            f"<div class='count'>{count}</div></div>"
        )
    return "\n".join(rows)


def write_html(path, summary):
    metrics = summary["metrics"]
    flows = summary["flows"]
    flow_rows = []
    for flow in flows[:12]:
        seen = flow.get("server_name") or flow.get("dns_name") or "—"
        flow_rows.append(
            "<tr>"
            f"<td>{escape(flow['who'])}</td>"
            f"<td>{escape(flow['category'])}</td>"
            f"<td>{escape(seen)}</td>"
            f"<td>{flow['packets']}</td><td>{flow['bytes']}</td></tr>"
        )
    if not flow_rows:
        flow_rows.append("<tr><td colspan='5'>No conversations found.</td></tr>")
    talker_rows = "".join(
        f"<li>{escape(item['address'])}: {item['bytes']} bytes</li>" for item in summary["talkers"]
    ) or "<li>None</li>"
    highlights = "".join(f"<li>{escape(item)}</li>" for item in summary["highlights"])
    notes = "".join(f"<li>{escape(item)}</li>" for item in summary["notes"])
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>DPI report</title>
<style>
body {{ margin:0; font-family: Georgia, serif; color:#1c2430; background:#f6f8fb; }}
main {{ max-width:880px; margin:0 auto; padding:32px 20px 64px; }}
.lede {{ color:#5c6b7a; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; }}
.card, .panel {{ background:#fff; border:1px solid #e4e9ef; border-radius:12px; padding:14px 16px; }}
.card b {{ display:block; font-size:1.4rem; font-family:sans-serif; }}
.row {{ display:grid; grid-template-columns:190px 1fr 48px; gap:10px; align-items:center; margin:8px 0; font-family:sans-serif; font-size:.92rem; }}
.track {{ background:#eef2f6; border-radius:999px; height:10px; }}
.fill {{ background:#1f6feb; height:10px; border-radius:999px; }}
table {{ width:100%; border-collapse:collapse; font-family:sans-serif; font-size:.92rem; }}
th, td {{ text-align:left; padding:8px 6px; border-bottom:1px solid #e4e9ef; }}
</style></head><body><main>
<h1>DPI look at this traffic</h1>
<p class="lede">Nothing was decrypted. This page uses only what a network can already see: addresses, ports, sizes, timing, lookup names, and a server name if the handshake still shows it.</p>
<div class="cards">
<div class="card"><b>{metrics['packet_count']}</b>packets</div>
<div class="card"><b>{metrics['duration_seconds']}s</b>time span</div>
<div class="card"><b>{metrics['packets_per_second']}</b>packets per second</div>
<div class="card"><b>{metrics['total_payload_bytes']}</b>payload bytes</div>
</div>
<h2>Warnings</h2><div class="panel"><ul>{''.join(f'<li>{escape(item)}</li>' for item in summary.get('alerts') or ['None'])}</ul></div>
<h2>Devices active</h2><div class="panel"><p>{escape(str(len(summary.get('devices') or [])))} local device(s). {escape(', '.join(item['address'] for item in summary.get('devices') or []) or 'None seen.')}</p><p>This is who talked during the check, or who answered on the local network. A silent device is not listed. This is not a scan of the public internet.</p></div>
<h2>Traffic mix</h2><div class="panel">{_bars(sorted(summary['categories'].items(), key=lambda item: -item[1]))}</div>
<p>Source: {escape(summary['source'])}. Owner: Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.</p>
<h2>Busiest addresses</h2><div class="panel"><ul>{talker_rows}</ul></div>
<h2>Conversations</h2>
<div class="panel"><table><thead><tr><th>Who talked</th><th>Best guess</th><th>Name seen</th><th>Packets</th><th>Bytes</th></tr></thead>
<tbody>{''.join(flow_rows)}</tbody></table></div>
<h2>How to read this</h2><ul>{notes}</ul>
</main></body></html>"""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(html)
