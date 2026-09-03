"""Zeek TSV/JSON-lines normalizer for conn.log/http.log/dns.log style events."""
import json


def normalize_json(line: str):
    obj = json.loads(line)
    return {
        "source": "zeek",
        "timestamp": obj.get("ts"),
        "event_type": obj.get("_path", "unknown"),
        "src_ip": obj.get("id.orig_h", "N/A"),
        "src_port": obj.get("id.orig_p", 0),
        "dst_ip": obj.get("id.resp_h", "N/A"),
        "dst_port": obj.get("id.resp_p", 0),
        "proto": obj.get("proto", ""),
        "service": obj.get("service", ""),
        "duration": obj.get("duration"),
        "orig_bytes": obj.get("orig_bytes", 0),
        "resp_bytes": obj.get("resp_bytes", 0),
        "raw": obj,
    }
