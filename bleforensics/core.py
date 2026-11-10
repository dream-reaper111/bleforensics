"""BTSnoop and classic PCAP HCI H4 parsing with cautious metadata extraction."""

from datetime import datetime, timezone
import hashlib
import re
import struct

MAX_FILE = 50_000_000
MAX_PACKET = 65535
BTSNOOP_UNIX_OFFSET_US = 0x00DC_DDB3_0F2F_8000


def iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


def hci_metadata(packet: bytes) -> dict:
    if not packet:
        raise ValueError("empty HCI packet")
    kind = packet[0]
    out = {"hci_type": {1: "command", 2: "acl", 3: "sco", 4: "event", 5: "iso"}.get(kind, "unknown")}
    if kind == 4:
        if len(packet) < 3 or len(packet) != 3 + packet[2]:
            raise ValueError("truncated HCI event")
        code = packet[1]
        payload = packet[3:]
        out["event_code"] = code
        if code == 5 and len(payload) >= 4:
            out.update({"event": "disconnect", "handle": int.from_bytes(payload[1:3], "little"), "reason_code": payload[3]})
        elif code == 0x3E and payload:
            out["le_subevent"] = payload[0]
            if payload[0] == 1 and len(payload) >= 19:
                out.update({"event": "le_connection_complete", "status": payload[1],
                            "handle": int.from_bytes(payload[2:4], "little"),
                            "peer_address_type": payload[5],
                            "interval_units_1_25ms": int.from_bytes(payload[12:14], "little"),
                            "latency": int.from_bytes(payload[14:16], "little"),
                            "supervision_timeout_units_10ms": int.from_bytes(payload[16:18], "little")})
            elif payload[0] == 2 and len(payload) >= 2:
                out.update({"event": "le_advertising_report", "report_count": payload[1]})
        else:
            out["event"] = "hci_event"
    elif kind == 1:
        if len(packet) < 4 or len(packet) != 4 + packet[3]:
            raise ValueError("truncated HCI command")
        out["opcode"] = int.from_bytes(packet[1:3], "little")
    elif kind == 2:
        if len(packet) < 5 or len(packet) != 5 + int.from_bytes(packet[3:5], "little"):
            raise ValueError("truncated ACL packet")
        out["handle"] = int.from_bytes(packet[1:3], "little") & 0x0FFF
        payload = packet[5:]
        if len(payload) >= 4:
            cid = int.from_bytes(payload[2:4], "little")
            out["l2cap_cid"] = cid
            out["l2cap_length"] = int.from_bytes(payload[:2], "little")
            if cid == 4 and len(payload) >= 5:
                out["att_opcode"] = payload[4]
    return out


def btsnoop(data: bytes) -> list[dict]:
    if len(data) < 16 or data[:8] != b"btsnoop\0" or int.from_bytes(data[8:12], "big") != 1:
        raise ValueError("invalid BTSnoop header")
    if int.from_bytes(data[12:16], "big") != 1002:
        raise ValueError("unsupported BTSnoop datalink; expected H4")
    records = []
    pos = 16
    while pos < len(data):
        if pos + 24 > len(data):
            raise ValueError("truncated BTSnoop record header")
        original, included, flags, dropped, stamp = struct.unpack_from(">IIIIQ", data, pos)
        pos += 24
        if included > MAX_PACKET or original < included or pos + included > len(data):
            raise ValueError("invalid BTSnoop packet length")
        packet = data[pos:pos + included]
        pos += included
        metadata = hci_metadata(packet)
        records.append({"timestamp": iso((stamp - BTSNOOP_UNIX_OFFSET_US) / 1_000_000),
                        "direction_flags": flags, "dropped_cumulative": dropped,
                        "captured_length": included, "original_length": original,
                        "packet_hex": packet.hex(), **metadata})
    return records


def pcap(data: bytes) -> list[dict]:
    if len(data) < 24:
        raise ValueError("truncated PCAP header")
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, divisor = "<", 1_000_000
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, divisor = ">", 1_000_000
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, divisor = "<", 1_000_000_000
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, divisor = ">", 1_000_000_000
    else:
        raise ValueError("invalid PCAP magic")
    major, minor = struct.unpack_from(endian + "HH", data, 4)
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    if (major, minor) != (2, 4) or linktype != 187:
        raise ValueError("unsupported PCAP version or link type; expected Bluetooth HCI H4 (187)")
    records = []
    pos = 24
    while pos < len(data):
        if pos + 16 > len(data):
            raise ValueError("truncated PCAP record header")
        sec, fraction, included, original = struct.unpack_from(endian + "IIII", data, pos)
        pos += 16
        if included > MAX_PACKET or original < included or pos + included > len(data):
            raise ValueError("invalid PCAP packet length")
        packet = data[pos:pos + included]
        pos += included
        records.append({"timestamp": iso(sec + fraction / divisor), "captured_length": included,
                        "original_length": original, "packet_hex": packet.hex(), **hci_metadata(packet)})
    return records


BTMON_TIME = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?)\s+([<>])\s+(HCI Event|HCI Command|ACL Data):\s*(.*)$")


def btmon(text: str) -> list[dict]:
    events = []
    for line in text.splitlines():
        match = BTMON_TIME.match(line)
        if not match:
            continue
        stamp, direction, kind, detail = match.groups()
        dt = datetime.fromisoformat(stamp).replace(tzinfo=timezone.utc)
        events.append({"timestamp": dt.isoformat(), "direction": direction, "hci_type": kind.lower(),
                       "summary": detail[:512], "timestamp_assumption": "naive btmon timestamp treated as UTC"})
    if not events:
        raise ValueError("no supported timestamped btmon lines")
    return events


def analyze(data: bytes, fmt: str) -> dict:
    if len(data) > MAX_FILE:
        raise ValueError("evidence exceeds 50 MB")
    if fmt == "btsnoop":
        events = btsnoop(data)
    elif fmt == "pcap":
        events = pcap(data)
    elif fmt == "btmon":
        events = btmon(data.decode("utf-8", "replace"))
    else:
        raise ValueError("unsupported format")
    events.sort(key=lambda x: x["timestamp"])
    sessions = {}
    for event in events:
        handle = event.get("handle")
        if handle is None:
            continue
        session = sessions.setdefault(str(handle), {"handle": handle, "first_seen": event["timestamp"], "last_seen": event["timestamp"], "events": 0, "disconnect_reason": None})
        session["last_seen"] = event["timestamp"]
        session["events"] += 1
        if event.get("event") == "disconnect":
            session["disconnect_reason"] = event["reason_code"]
    return {"sha256": hashlib.sha256(data).hexdigest(), "format": fmt, "capture_scope": "host HCI; not all over-the-air packets", "event_count": len(events), "events": events, "sessions": list(sessions.values()), "packet_loss_indicator": max((x.get("dropped_cumulative", 0) for x in events), default=0)}


def export_pcap(events: list[dict]) -> bytes:
    output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, MAX_PACKET, 187))
    for event in events:
        if "packet_hex" not in event:
            raise ValueError("text-only btmon cannot export packet PCAP")
        packet = bytes.fromhex(event["packet_hex"])
        stamp = datetime.fromisoformat(event["timestamp"]).timestamp()
        sec = int(stamp)
        micros = round((stamp - sec) * 1_000_000)
        output += struct.pack("<IIII", sec, micros, len(packet), event["original_length"])
        output += packet
    return bytes(output)
