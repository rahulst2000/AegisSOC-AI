import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adversary.models import AssessmentResult
from app.security_improvement.schemas import MitreCoverageItem

# Standard MITRE ATT&CK reference metadata
MITRE_TECHNIQUE_METADATA = {
    "T1110.001": {
        "name": "Password Guessing",
        "tactics": ["Credential Access"],
    },
    "T1110.003": {
        "name": "Password Spraying",
        "tactics": ["Credential Access"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
    },
    "T1078.003": {
        "name": "Local Accounts (Privileged)",
        "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation"],
    },
}


async def get_mitre_coverage_matrix(
    db: AsyncSession,
    tenant_id: uuid.UUID,
) -> list[MitreCoverageItem]:
    """
    Builds the authoritative MITRE ATT&CK validation matrix from actual simulation test results.
    Never invents or fabricates coverage metrics.
    """
    # Fetch most recent assessment result per technique for the tenant
    stmt = (
        select(AssessmentResult)
        .where(AssessmentResult.tenant_id == tenant_id)
        .order_by(AssessmentResult.completed_at.desc())
    )
    res = await db.execute(stmt)
    all_results = res.scalars().all()

    # Map latest result by technique_id
    latest_by_tech: dict[str, AssessmentResult] = {}
    for r in all_results:
        if r.technique_id not in latest_by_tech:
            latest_by_tech[r.technique_id] = r

    matrix: list[MitreCoverageItem] = []

    for tech_id, meta in MITRE_TECHNIQUE_METADATA.items():
        latest = latest_by_tech.get(tech_id)
        if latest:
            matrix.append(
                MitreCoverageItem(
                    technique_id=tech_id,
                    technique_name=meta["name"],
                    tactics=meta["tactics"],
                    simulation=latest.simulation_status,
                    detection=latest.detection_status,
                    correlation=latest.correlation_status,
                    investigation=latest.investigation_status,
                    response=latest.response_status,
                    verification=latest.verification_status,
                    overall=latest.overall_result,
                )
            )
        else:
            matrix.append(
                MitreCoverageItem(
                    technique_id=tech_id,
                    technique_name=meta["name"],
                    tactics=meta["tactics"],
                    simulation="NOT_TESTED",
                    detection="NOT_TESTED",
                    correlation="NOT_TESTED",
                    investigation="NOT_TESTED",
                    response="NOT_TESTED",
                    verification="NOT_TESTED",
                    overall="NOT_TESTED",
                )
            )

    return matrix
