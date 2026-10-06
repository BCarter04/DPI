"""A simple window for the same DPI reading.

Copyright (c) 2023-2026 Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.

What it does now
    Lets a person run the demo or a live check and open the report without
    typing the command. The report can name YouTube, Netflix, Google, and
    other common apps when the site name is visible.

What it will do
    A later build can wrap this window as an .exe. The app list can grow.
    It will not show the video title or the search text.
"""

import os
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from dpi.analyze import analyze
from dpi.capture import build_demo_packets, capture_live, choose_live_interface, list_interfaces
from dpi.devices import devices_on_link
from dpi.cli import write_outputs


def open_report(path):
    if os.name == "nt":
        os.startfile(path)  # noqa: S606 - opens the report the user just made
    else:
        os.system(f'xdg-open "{path}"')


def launch():
    root = tk.Tk()
    root.title("DPI")
    root.geometry("640x460")
    status = tk.StringVar(value="Ready. The demo needs no admin rights. A live check does.")
    count = tk.StringVar(value="80")
    chosen = tk.StringVar(value="auto")

    def set_status(text):
        status.set(text)
        root.update_idletasks()

    def run_job(kind):
        def work():
            try:
                if kind == "check":
                    from dpi.doctor import check_computer, exe_ready
                    text = "\n".join(check_computer() + [exe_ready()])
                    set_status(text)
                    messagebox.showinfo("DPI check", text)
                    return
                if kind == "demo":
                    packets = build_demo_packets()
                    source = "built-in demo (fake packets, not your network)"
                    folder = "dpi-output"
                else:
                    iface = chosen.get()
                    if iface == "auto":
                        iface = choose_live_interface()
                    set_status(f"Listening on {iface}. Browse a page.")
                    packets = capture_live(iface, int(count.get() or "80"))
                    if not packets:
                        raise RuntimeError(f"No packets were read on {iface}. Open this window as Administrator and install Npcap.")
                    source = f"live capture on {iface}, the network this computer is using"
                    folder = "live-output"
                summary = analyze(packets, source)
                if kind == "live":
                    from dpi.devices import role_for
                    linked = devices_on_link(iface)
                    if linked:
                        summary["devices"] = [{"address": address, "how": "answered on the local network", "role": role_for(address)} for address in linked]
                        summary["highlights"].insert(0, f"{len(linked)} device(s) answered on the local network: {', '.join(linked)}.")
                path = write_outputs(summary, folder)
                roles = ", ".join(f"{item['address']} ({item.get('role') or 'seen'})" for item in summary.get("devices") or []) or "no local address"
                from dpi.report import top_guess
                warning = (summary.get("alerts") or ["No warning in this capture."])[0]
                apps = ", ".join(summary.get("apps") or []) or "none named"
                home = ", ".join(name for name in ("Address setup (DHCP)", "Phones, printers, and TVs") if (summary.get("categories") or {}).get(name)) or "not seen"
                set_status(f"Wrote {path}. Score: {summary.get('score')}/100. Gateway guess: {summary.get('gateway')}. Local network: {summary.get('subnet')}. DNS: {summary.get('dns_health')}. Apps: {apps}. Devices: {len(summary.get('devices') or [])}. Home setup: {home}. Top guess: {top_guess(summary)}. Warning: {warning}. Why it may be slow: {summary.get('why_slow')}. {roles}")
                open_report(path)
            except Exception as error:
                set_status("The check failed.")
                if isinstance(error, IndexError):
                    text = (
                        "Could not read one packet: it was cut off.\n\n"
                        "A live packet arrived shorter than a full name lookup or handshake. "
                        "DPI stopped on that packet instead of guessing. "
                        "This is not a decrypt error, and it does not mean Npcap is missing.\n\n"
                        "Try the demo first. For a live check, close this window, open it with Run as administrator, and try again."
                    )
                else:
                    text = str(error)
                messagebox.showerror("DPI", text)
        threading.Thread(target=work, daemon=True).start()

    frame = ttk.Frame(root, padding=16)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="DPI", font=("Georgia", 22)).pack(anchor="w")
    ttk.Label(frame, text="Reads packets in plain words. Does not decrypt anything.").pack(anchor="w", pady=(0, 12))
    ttk.Label(frame, text="Network card").pack(anchor="w")
    names = ["auto"]
    try:
        names.extend(list_interfaces())
    except Exception:
        pass
    ttk.Combobox(frame, textvariable=chosen, values=names, state="readonly").pack(fill="x", pady=(0, 8))
    row = ttk.Frame(frame)
    row.pack(fill="x", pady=(0, 12))
    ttk.Label(row, text="Packets to read").pack(side="left")
    ttk.Entry(row, textvariable=count, width=8).pack(side="left", padx=8)
    ttk.Button(frame, text="Check this network (live)", command=lambda: run_job("live")).pack(fill="x", pady=4)
    ttk.Button(frame, text="Check this computer", command=lambda: run_job("check")).pack(fill="x", pady=4)
    ttk.Button(frame, text="Run demo (fake packets)", command=lambda: run_job("demo")).pack(fill="x", pady=4)
    ttk.Label(frame, text="Live reads the network this computer is connected to. On Windows, open this window as Administrator after Npcap is installed. The demo does not use your network.", wraplength=580).pack(anchor="w", pady=(8, 0))
    ttk.Label(frame, textvariable=status, wraplength=580).pack(anchor="w", pady=16)
    ttk.Label(frame, text="Owner: Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.").pack(anchor="w")
    root.mainloop()
