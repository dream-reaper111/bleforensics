import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from bleforensics.core import BTSNOOP_UNIX_OFFSET_US, analyze, export_pcap, hci_metadata
from bleforensics.cli import main

EVENT = bytes.fromhex("04050400010013")


def fixture_btsnoop():
    header = b"btsnoop\0" + struct.pack(">II", 1, 1002)
    record = struct.pack(">IIIIQ", len(EVENT), len(EVENT), 0, 0, BTSNOOP_UNIX_OFFSET_US + 1_000_000)
    return header + record + EVENT


class Tests(unittest.TestCase):
    def test_btsnoop_and_pcap_roundtrip(self):
        data = fixture_btsnoop()
        report = analyze(data, "btsnoop")
        self.assertEqual(report["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(report["sessions"][0]["disconnect_reason"], 19)
        pcap = export_pcap(report["events"])
        self.assertEqual(analyze(pcap, "pcap")["events"][0]["event"], "disconnect")

    def test_acl_and_malformed(self):
        acl = bytes.fromhex("0201000500010004000a")
        self.assertEqual(hci_metadata(acl)["att_opcode"], 10)
        for data in (fixture_btsnoop()[:-1], b"btsnoop\0" + struct.pack(">II", 1, 1001), b"bad"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                analyze(data, "btsnoop")
        with self.assertRaises(ValueError):
            analyze(b"\xd4\xc3\xb2\xa1", "pcap")

    def test_btmon_and_cli(self):
        text = b"2026-11-09 12:00:00.123 > HCI Event: Disconnect Complete\n"
        self.assertEqual(analyze(text, "btmon")["event_count"], 1)
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / "input.log").write_bytes(fixture_btsnoop())
            self.assertEqual(main([str(p / "input.log"), "--format", "btsnoop", "--output", str(p / "report.json"), "--pcap-output", str(p / "out.pcap")]), 0)
            self.assertEqual(json.loads((p / "report.json").read_text())["event_count"], 1)
            self.assertEqual(analyze((p / "out.pcap").read_bytes(), "pcap")["event_count"], 1)


if __name__ == "__main__":
    unittest.main()
