#!/usr/bin/env python3
"""Offline SOC ingestion utility for Suricata, Zeek and Wazuh JSON logs."""
import argparse
import json
from pathlib import Path
from sentinel_soc.integrations.eve import normalize as normalize_suricata
from sentinel_soc.integrations.zeek import normalize_json as normalize_zeek
from sentinel_soc.integrations.wazuh import normalize as normalize_wazuh

PARSERS = {"suricata": normalize_suricata, "zeek": normalize_zeek, "wazuh": normalize_wazuh}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source", choices=PARSERS)
    ap.add_argument("file")
    ap.add_argument("--output", default="normalized_events.jsonl")
    args = ap.parse_args()
    parser = PARSERS[args.source]
    count = 0
    with Path(args.file).open("r", encoding="utf-8", errors="replace") as src, Path(args.output).open("w", encoding="utf-8") as dst:
        for line in src:
            line = line.strip()
            if not line:
                continue
            try:
                event = parser(line)
                dst.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
                count += 1
            except Exception as exc:
                dst.write(json.dumps({"source": args.source, "parse_error": str(exc), "raw_line": line}, ensure_ascii=False) + "\n")
    print(f"Eventos normalizados: {count}")

if __name__ == "__main__":
    main()
