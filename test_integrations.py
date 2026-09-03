from sentinel_soc.core.risk import RiskInput, score
from sentinel_soc.integrations.eve import normalize as suricata
from sentinel_soc.integrations.wazuh import normalize as wazuh


def test_risk_is_bounded():
    assert 0 <= score(RiskInput("CRÍTICA", 100, 100, 100, 100)) <= 100


def test_suricata_normalization():
    e = suricata('{"event_type":"alert","src_ip":"10.0.0.5","dest_ip":"10.0.0.1","src_port":1234,"dest_port":80,"proto":"TCP","alert":{"signature":"Test","severity":1}}')
    assert e["source"] == "suricata"
    assert e["signature"] == "Test"


def test_wazuh_normalization():
    e = wazuh('{"timestamp":"2026-01-01T00:00:00Z","rule":{"id":"100001","level":10,"description":"test"},"agent":{"id":"001","name":"lab"},"data":{"srcip":"10.0.0.5"}}')
    assert e["rule_id"] == "100001"
    assert e["src_ip"] == "10.0.0.5"
