"""AegisSOC Adversary Validation (AegisRed) package."""

from app.adversary.executor import execute_adversary_assessment
from app.adversary.models import AdversaryAssessment, AssessmentResult
from app.adversary.scenarios import SCENARIO_REGISTRY, AdversaryScenarioDefinition
from app.adversary.scope import validate_assessment_scope
from app.adversary.service import AdversaryService

__all__ = [
    "AdversaryAssessment",
    "AdversaryScenarioDefinition",
    "AssessmentResult",
    "AdversaryService",
    "SCENARIO_REGISTRY",
    "execute_adversary_assessment",
    "validate_assessment_scope",
]
