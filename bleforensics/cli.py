import argparse
import json
from pathlib import Path
import sys
from .hardware import capabilities

from .core import MAX_FILE, analyze, export_pcap


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv == ["hardware"]:
        print(json.dumps(capabilities(), indent=2))
        return 0
    parser = argparse.ArgumentParser(prog="bleforensics")
    parser.add_argument("input", type=Path)
    parser.add_argument("--format", choices=["btsnoop", "pcap", "btmon"], required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--pcap-output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.input.stat().st_size > MAX_FILE:
            raise ValueError("evidence exceeds 50 MB")
        data = args.input.read_bytes()
        report = analyze(data, args.format)
        if args.pcap_output:
            args.pcap_output.write_bytes(export_pcap(report["events"]))
        result = json.dumps(report, indent=2) + "\n"
        if args.output:
            args.output.write_text(result)
        else:
            print(result, end="")
        return 0
    except (OSError, ValueError, OverflowError) as exc:
        print(f"bleforensics: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
