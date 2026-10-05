from __future__ import annotations

import argparse
import json
from pathlib import Path

from elevadr_modules.registry import get_module, list_modules
from elevadr_modules.zeek import load_zeek_directory, run_zeek_on_pcap


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run standalone eleVADR Zeek analysis modules.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="List registered modules")

    run = subparsers.add_parser("run", help="Run one module")
    run.add_argument("module_id")
    source = run.add_mutually_exclusive_group(required=True)
    source.add_argument("--logs", type=Path, help="Directory containing Zeek logs")
    source.add_argument("--pcap", type=Path, help="PCAP/PCAPNG to process with Zeek")
    run.add_argument("--zeek-output", type=Path, help="Keep Zeek output in this directory")
    run.add_argument("--json-out", type=Path, help="Write structured result JSON")

    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "list":
        print(json.dumps(list_modules(), indent=2))
        return 0

    module = get_module(args.module_id)
    if args.logs:
        context = load_zeek_directory(args.logs)
    else:
        context, zeek_dir = run_zeek_on_pcap(args.pcap, args.zeek_output)
        print(f"Zeek output: {zeek_dir}")

    result = module.analyze(context)
    payload = result.to_dict()
    print(json.dumps(payload, indent=2, default=str))
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
