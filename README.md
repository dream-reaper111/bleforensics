# BLEForensics

BLEForensics performs bounded offline analysis of Bluetooth HCI evidence. It accepts BTSnoop H4 (datalink 1002), classic PCAP with Bluetooth HCI H4 link type 187, and a limited timestamped btmon text form. It reports HCI command/event and ACL metadata, LE connection and advertisement event indicators, ATT/L2CAP metadata, session handles, disconnect reasons, cumulative drop indicators when BTSnoop reports them, normalized UTC timestamps, and original evidence SHA-256. It can export binary events as Wireshark-compatible PCAP H4. The input file is never modified.

```sh
python3 -m bleforensics.cli capture.btsnoop --format btsnoop --output timeline.json --pcap-output timeline.pcap
```

The limit is 50 MB per file and 65,535 bytes per packet. HCI evidence does not include every over-the-air packet. Protected session contents are not decrypted or bypassed. See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), [HARDWARE.md](HARDWARE.md), [DEPENDENCIES.md](DEPENDENCIES.md), and [VALIDATION_REPORT.md](VALIDATION_REPORT.md).
