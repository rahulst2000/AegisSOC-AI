from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True)
class CorrelationRuleDefinition:
    """Configurable correlation rule definition specifying matching dimensions and sliding time windows."""

    rule_id: str
    name: str
    description: str
    dimension: Literal["source_ip", "username", "hostname", "mixed"]
    window_minutes: int
    min_detections: int = 1
    required_techniques: list[str] = field(default_factory=list)
    target_severity: str = "HIGH"


class CorrelationConfig:
    """Configurable correlation windows and defaults."""

    # Configurable windows (in minutes)
    BRUTE_FORCE_WINDOW_MINUTES: int = 5
    PASSWORD_SPRAY_WINDOW_MINUTES: int = 10
    FAILURE_THEN_SUCCESS_WINDOW_MINUTES: int = 10
    PRIVILEGED_ACCESS_WINDOW_MINUTES: int = 15
    DEFAULT_CORRELATION_WINDOW_MINUTES: int = 15
    MULTI_STAGE_INCIDENT_WINDOW_MINUTES: int = 30

    @classmethod
    def get_built_in_rules(cls) -> list[CorrelationRuleDefinition]:
        return [
            CorrelationRuleDefinition(
                rule_id="CORR-IP-BURST",
                name="Single Source IP Multi-Signal Correlation",
                description="Correlates repeated detections and authentication anomalies from the same source IP.",
                dimension="source_ip",
                window_minutes=cls.BRUTE_FORCE_WINDOW_MINUTES,
                min_detections=1,
            ),
            CorrelationRuleDefinition(
                rule_id="CORR-USER-ACCOUNT-TAKEOVER",
                name="User Account Takeover Chain",
                description=(
                    "Correlates credential guessing, successful login, and privileged activity "
                    "on a single user identity."
                ),
                dimension="username",
                window_minutes=cls.FAILURE_THEN_SUCCESS_WINDOW_MINUTES,
                min_detections=1,
                required_techniques=["T1078"],
            ),
            CorrelationRuleDefinition(
                rule_id="CORR-HOST-COMPROMISE",
                name="Host-Centric Multi-Vector Correlation",
                description="Correlates multi-phase attacker behaviors targeting a specific host asset.",
                dimension="hostname",
                window_minutes=cls.MULTI_STAGE_INCIDENT_WINDOW_MINUTES,
                min_detections=1,
            ),
        ]
