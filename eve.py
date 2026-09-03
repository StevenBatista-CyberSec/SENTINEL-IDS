"""Suricata EVE JSON normalizer.

Reads one JSON object per line and converts it into a normalized event dict.
No network actions are performed here; this module is safe for offline ingestion.
"""
import json
from datetime import datetime, timezone


def _timestamp(value):
    if not value:
        return datetime.now(timezone.utc).isoformat()
    return value


def normalize(line: str):
    obj = json.loads(line)
    event_type = obj.get("event_type", "unknown")
    alert = obj.get("alert", {}) or {}
    return {
        "source": "suricata",
        "timestamp": _timestamp(obj.get("timestamp")),
        "event_type": event_type,
        "signature": alert.get("signature", ""),
        "category": alert.get("category", ""),
        "severity": alert.get("severity", 3),
        "src_ip": obj.get("src_ip", "N/A"),
        "src_port": obj.get("src_port", 0),
        "dst_ip": obj.get("dest_ip", "N/A"),
        "dst_port": obj.get("dest_port", 0),
        "proto": obj.get("proto", ""),
        "flow_id": obj.get("flow_id"),
        "raw": obj,
    }
