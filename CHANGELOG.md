# Changelog

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
