"""Write the one-page report.

Copyright (c) 2023-2026 Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.

What it does now
    Writes report.html for both the demo and a live capture. The top block
    is Network status: packets, lookups, repeated packets, resets, apps,
    devices, and why it may be slow. The same function writes both reports.

What it will do
    Later pages can add charts. They should keep the same plain-language
    sentences so a new reader still understands the result.
"""

from html import escape


def _bars(pairs):
    """Draw one bar per guess. The number is a share of the packets, not a speed."""
    if not pairs:
        return "<p>Nothing to show.</p>"
    total = sum(count for _, count in pairs) or 1
    top = max(count for _, count in pairs) or 1
    rows = []
    for label, count in pairs:
        width = max(4, int(100 * count / top))
        share = round(100 * count / total)
        rows.append(
            "<div class='row'>"
            f"<div class='label'>{escape(str(label))}</div>"
            f"<div class='track'><div class='fill' style='width:{width}%'></div></div>"
            f"<div class='count'>{count} ({share}%)</div></div>"
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
            f"<td>{escape(flow.get('health') or '')}</td>"
            f"<td>{flow['packets']}</td><td>{flow['bytes']}</td><td>{escape(str(flow.get('duration') if flow.get('duration') is not None else '—'))}</td><td>{escape(str(flow.get('handshake_ms') if flow.get('handshake_ms') is not None else '—'))}</td></tr>"
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
.row {{ display:grid; grid-template-columns:190px 1fr 88px; gap:10px; align-items:center; margin:8px 0; font-family:sans-serif; font-size:.92rem; }}
.track {{ background:#eef2f6; border-radius:999px; height:10px; }}
.fill {{ background:#1f6feb; height:10px; border-radius:999px; }}
table {{ width:100%; border-collapse:collapse; font-family:sans-serif; font-size:.92rem; }}
th, td {{ text-align:left; padding:8px 6px; border-bottom:1px solid #e4e9ef; }}
</style></head><body><main>
<h1>DPI network reading</h1>
<p class="lede">Nothing was decrypted. This is the same reading for the demo and for a live network.</p>
<h2>Network status</h2>
<div class="panel"><pre>Packets            {metrics['packet_count']}
Packets/sec        {metrics['packets_per_second']}
Active talks       {len(summary.get('flows') or [])}
Name lookups       {len(summary.get('dns_times') or [])}
DNS health         {escape(summary.get('dns_health') or 'Not seen')}
Gateway guess      {escape(summary.get('gateway') or 'not seen')}
Local network      {escape(summary.get('subnet') or 'not seen')}
Reading score      {summary.get('score', '')}/100
Download bytes     {summary.get('download_bytes', 0)}
Upload bytes       {summary.get('upload_bytes', 0)}
Repeated packets   {metrics.get('repeated_sequences', 0)}
Resets             {metrics.get('resets', 0)}
Possible QUIC      {metrics.get('quic_packets', 0)}
Apps               {escape(', '.join(summary.get('apps') or []) or 'none named')}
Devices            {len(summary.get('devices') or [])}
Why it may be slow {escape(summary.get('why_slow') or '')}</pre></div>
<h2>Apps seen</h2><div class="panel"><ul>{''.join(f"<li>{escape(item['name'])}: confidence {escape(item['confidence'])}. Evidence: {escape(', '.join(item['evidence']) or 'name match')}</li>" for item in summary.get('apps_seen') or []) or '<li>No listed app name was visible.</li>'}</ul><p>This is a name match, not the page or the video. Demo and live use the same list.</p></div>
<h2>DNS health</h2>
<div class="panel"><pre>Status        {escape((summary.get('dns_summary') or {}).get('health') or 'Not seen')}
Answered      {(summary.get('dns_summary') or {}).get('answered', 0)}
Failed        {(summary.get('dns_summary') or {}).get('failed', 0)}
Average       {escape(str((summary.get('dns_summary') or {}).get('average_ms') if (summary.get('dns_summary') or {}).get('average_ms') is not None else 'not timed'))} ms</pre>
<p>The same counts are used for the demo and a live run. A lookup is timed only if both the question and the answer were captured.</p>
<ul>{''.join(f"<li>{escape(item['name'])}: {item['ms']} ms</li>" for item in summary.get('dns_times') or []) or '<li>No lookup was timed.</li>'}</ul>
<h2>Warnings</h2><div class="panel"><ul>{''.join(f'<li>{escape(item)}</li>' for item in summary.get('alerts') or ['No warning in this capture.'])}</ul><p>A warning is a hint from this capture. It is not proof of a broken router or a broken website.</p></div>
<h2>Devices active</h2><div class="panel"><p>{escape(str(len(summary.get('devices') or [])))} local device(s). {escape(', '.join(item['address'] for item in summary.get('devices') or []) or 'None seen.')}</p><p>This is who talked during the check, or who answered on the local network. A silent device is not listed. This is not a scan of the public internet.</p></div>
<h2>What this page is doing</h2>
<div class="panel">
<p>The program groups packets into talks. A talk is both directions between two addresses and ports.</p>
<p>Traffic mix is the count of those packets by best guess. A best guess comes from the port, such as 443 for encrypted web, or from a visible site name such as bbc.co.uk. It is not the page, the video, or the search.</p>
<p>Download and upload bytes are payload sizes in this capture, not a broadband speed test. The reading score drops if packets were repeated, a talk was reset, or a name lookup failed.</p>
</div>
<h2>Traffic mix</h2><div class="panel"><p>Each bar is a share of the packets in this capture. A longer bar means more packets of that kind, not a faster connection.</p>{_bars(sorted(summary['categories'].items(), key=lambda item: -item[1]))}</div>
<p>Source: {escape(summary['source'])}. Owner: Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.</p>
<h2>Busiest addresses</h2><div class="panel"><ul>{talker_rows}</ul></div>
<h2>Conversations</h2>
<div class="panel"><table><thead><tr><th>Who talked</th><th>Best guess</th><th>Name seen</th><th>Talk health</th><th>Packets</th><th>Bytes</th><th>Seconds</th><th>Handshake ms</th></tr></thead>
<tbody>{''.join(flow_rows)}</tbody></table></div>
<h2>Limits of this reading</h2>
<div class="panel">
<p>Nothing was decrypted. A port is only a hint. A short check can miss a problem. Site names are remembered on this computer for 7 days, and that is not a malware check.</p>
</div>
</main></body></html>"""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(html)
