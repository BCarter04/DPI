# Changelog

## 2.28.0

- The window shows the same slow-link sentence as the report.
- Demo and live use the same sentence. A short check can still miss a problem.

## 2.27.0

- The window shows the same top traffic guess as the report.
- Demo and live use the same share. It is not a speed test.

## 2.26.0

- The report names the top traffic guess and its share of packets.
- Demo and live use the same line. It is not a speed test.

## 2.25.0

- The report explains the reply gap. A dash means only one side was seen.
- A test checks an empty report and that a strange name cannot become a script.

## 2.24.0

- The window shows the same device role as the report after a demo or a live check.
- A live address ending in .1 is still only a likely router.

## 2.23.0

- Each local address has a plain role. An address ending in .1 is called a likely router.
- Demo and live use the same label. It is not a device name.

## 2.22.0

- Each talk can show a reply gap: the time until the other side was seen.
- This is not a ping test. Demo and live use the same column.

## 2.21.0

- The report has a Home setup line for DHCP and for phones, printers, and TVs.
- A warning is no longer added when another warning is already there.

## 2.20.0

- The report states the limits: no decryption, a port is a hint, a short check can miss a problem.
- A test checks that a site name is new only once in the 7-day memory.

## 2.19.0

- Site names are remembered for 7 days, with the day they were first seen.
- Demo and live use the same memory. It is not a malware check.

## 2.18.0

- Each timed name lookup is listed under DNS health, with its milliseconds.
- Demo and live use the same list.

## 2.17.0

- The report has a Handshake ms column. A dash means the start and reply were not both seen.
- Demo and live use the same column.

## 2.16.0

- A talk can show a handshake time when both the start and the reply were seen.
- Demo and live use the same timing. It is not a ping test.

## 2.15.0

- An empty capture now writes a full report instead of stopping.
- Demo and live use the same empty-capture note.

## 2.14.0

- A warning names the address that moved at least half of the payload.
- Demo and live use the same warning.

## 2.13.0

- Each talk shows how many seconds it was visible.
- `--port 443` keeps one port. `--config dpi.yml` can set the packet limit.
- `--log dpi.log` writes a plain start line. A test checks YouTube, Netflix, and BBC names.

## 2.12.0

- Warnings are a block on the report, for the demo and a live run.
- A local network guess, such as 10.0.0.0/24, sits next to the gateway guess.
- A slow name lookup, over 200 ms, is called out.

## 2.11.0

- Each traffic-mix bar now shows a packet count and a percentage.
- Demo and live use the same bars.

## 2.10.0

- The report explains what it is doing, and what the traffic mix bars mean.
- The same explanation is used for the demo and a live run.

## 2.9.0

- `--reach bbc.co.uk` says if that name was visible. Demo and live use the same check.
- The report names the busiest address in the capture.

## 2.8.0

- A demo or live run now says which site names are new since the last run on this computer.
- The list is saved in dpi-seen.json. It is not a malware check.

## 2.7.0

- DNS health now shows answered, failed, and average time on the demo and live report.
- A live capture with no packets explains Npcap, Administrator, and the network card in plain words.

## 2.6.0

- A short live packet no longer needs to stop the reading with "list index out of range".
- The window names this "Could not read one packet: it was cut off" instead of "list index out of range".
- Demo and live still use the same report.

## 2.5.0

- Download and upload bytes on the demo and live status block.
- These are payload sizes in the capture, not a broadband speed test.

## 2.4.0

- A reading score out of 100, from repeats, resets, and failed lookups.
- `--app YouTube` keeps only talks that matched that app. Demo and live both support it.
- Ports 5353 and 1900 are labelled "Phones, printers, and TVs". Those devices use them to announce themselves on the home network.

## 2.3.0

- Apps seen now lists the name, the confidence, and the site that matched.
- Demo and live use the same list.

## 2.2.0

- Watch mode now reprints the full Network status each round, for a live network.
- The demo still uses the same status block, so you can check the reading first.

## 2.1.0

- DNS health and a gateway guess on the demo and live report.
- Talk health for each conversation.
- A longer app list, including UK sites, shown in the traffic mix.
- Network status at the top of the report.
- Computer check, setup, and a Windows exe build script.

The demo and live run use the same reading. Nothing is decrypted.
