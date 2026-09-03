"""Wazuh alert JSON normalizer."""
import json


def normalize(line: str):
    obj = json.loads(line)
    rule = obj.get("rule", {}) or {}
    agent = obj.get("agent", {}) or {}
    return {
        "source": "wazuh",
        "timestamp": obj.get("timestamp"),
        "event_type": "wazuh_alert",
        "rule_id": rule.get("id", ""),
        "rule_level": rule.get("level", 0),
        "description": rule.get("description", ""),
        "groups": rule.get("groups", []),
        "agent_id": agent.get("id", ""),
        "agent_name": agent.get("name", ""),
        "src_ip": obj.get("data", {}).get("srcip", "N/A") if isinstance(obj.get("data"), dict) else "N/A",
        "raw": obj,
    }
