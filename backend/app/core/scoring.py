"""Configurable weights for the transparent risk engine and severity bands.

Every number the risk engine produces traces back to one of these weights and a
piece of evidence; nothing is random. Override by constructing `RiskWeights(...)`
and passing it to the engine.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskWeights:
    criticality_multiplier: int = 5  # points per criticality level (1..5)
    criticality_cap: int = 25
    per_signal: int = 4  # points per suspicious event on the host
    signal_cap: int = 20
    credential_access: int = 15
    lateral_in: int = 15  # host was moved *into*
    lateral_out: int = 5  # host was used to move *out*
    unusual_auth: int = 10
    data_access: int = 15  # sensitive data read from this host
    chain_position_max: int = 10  # proximity to the attack frontier
    incident_per_extra_host: int = 2  # added per compromised host beyond the first


DEFAULT_WEIGHTS = RiskWeights()

# Incident severity bands by 0..100 risk score.
SEVERITY_BANDS = ((80, "critical"), (60, "high"), (40, "medium"), (0, "low"))


def severity_for(score: int) -> str:
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "low"
