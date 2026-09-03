"""Risk scoring utilities shared by SENTINEL SOC integrations."""
from dataclasses import dataclass

@dataclass(frozen=True)
class RiskInput:
    severity: str
    confidence: float = 50.0
    frequency: float = 0.0
    asset_criticality: float = 50.0
    source_reputation: float = 50.0

SEVERITY = {"INFO": 5, "BAJA": 20, "MEDIA": 45, "ALTA": 70, "CRÍTICA": 95, "CRITICA": 95}

def score(r: RiskInput) -> float:
    severity = SEVERITY.get(r.severity.upper(), 30)
    confidence = max(0, min(100, r.confidence))
    frequency = max(0, min(100, r.frequency))
    criticality = max(0, min(100, r.asset_criticality))
    reputation = max(0, min(100, r.source_reputation))
    value = (severity * .40 + confidence * .25 + frequency * .10 + criticality * .15 + reputation * .10)
    return round(max(0.0, min(100.0, value)), 2)
