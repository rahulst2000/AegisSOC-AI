from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_tenant_context, require_roles
from app.detection.mitre_mapper import MitreAttackCatalog
from app.detection.models import DetectionRule
from app.detection.registry import global_rule_registry
from app.detection.schemas import DetectionRuleCreate, DetectionRuleRead, DetectionRuleUpdate
from app.security.roles import Role
from app.security.tenant import TenantContext
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/rules", tags=["Detection Rules"])


@router.get("", response_model=list[DetectionRuleRead], status_code=status.HTTP_200_OK)
async def list_rules(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    enabled: bool | None = Query(None),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Lists rules accessible to the tenant:
    - Global system rules (tenant_id is NULL)
    - Tenant-specific rules (tenant_id == authenticated tenant)
    Never leaks custom rules belonging to another tenant.
    """
    stmt = (
        select(DetectionRule)
        .where(
            or_(
                DetectionRule.tenant_id.is_(None),
                DetectionRule.tenant_id == ctx.tenant_id,
            )
        )
        .order_by(DetectionRule.created_at.desc())
    )
    if enabled is not None:
        stmt = stmt.where(DetectionRule.enabled == enabled)

    stmt = stmt.offset(skip).limit(limit)
    res = await db.execute(stmt)
    return list(res.scalars().all())


@router.get("/{rule_id}", response_model=DetectionRuleRead, status_code=status.HTTP_200_OK)
async def get_rule(
    rule_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves a detection rule by rule_id if visible to the tenant.
    """
    stmt = select(DetectionRule).where(
        DetectionRule.rule_id == rule_id,
        or_(
            DetectionRule.tenant_id.is_(None),
            DetectionRule.tenant_id == ctx.tenant_id,
        ),
    )
    res = await db.execute(stmt)
    rule = res.scalars().first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found.",
        )
    return rule


@router.post(
    "",
    response_model=DetectionRuleRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            require_roles(
                [
                    Role.TENANT_ADMIN,
                    Role.SECURITY_ENGINEER,
                    Role.SECURITY_MANAGER,
                    Role.CISO,
                ]
            )
        )
    ],
)
async def create_rule(
    rule_in: DetectionRuleCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Creates a new custom detection rule scoped to the authenticated tenant.
    Validates MITRE ATT&CK techniques against the authoritative catalog.
    Only authorized security roles may create detection rules.
    """
    # Verify rule_id uniqueness
    existing_stmt = select(DetectionRule).where(
        DetectionRule.rule_id == rule_in.rule_id,
        or_(
            DetectionRule.tenant_id.is_(None),
            DetectionRule.tenant_id == ctx.tenant_id,
        ),
    )
    res = await db.execute(existing_stmt)
    if res.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Detection rule with rule_id '{rule_in.rule_id}' already exists.",
        )

    # Validate MITRE techniques
    for tech in rule_in.mitre_techniques:
        if not MitreAttackCatalog.validate_technique_id(tech):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid MITRE ATT&CK technique ID: '{tech}'.",
            )

    # Resolve tactics
    resolved_tactics = MitreAttackCatalog.resolve_tactics(rule_in.mitre_techniques)
    all_tactics = sorted(set(rule_in.mitre_tactics + resolved_tactics))

    rule = DetectionRule(
        rule_id=rule_in.rule_id,
        tenant_id=ctx.tenant_id,  # Strictly tenant-scoped
        name=rule_in.name,
        description=rule_in.description,
        version=rule_in.version,
        enabled=rule_in.enabled,
        severity=rule_in.severity.upper(),
        confidence=rule_in.confidence,
        event_types=[t.upper() for t in rule_in.event_types],
        conditions=rule_in.conditions,
        mitre_tactics=all_tactics,
        mitre_techniques=rule_in.mitre_techniques,
        tags=rule_in.tags,
    )
    db.add(rule)
    await db.flush()

    # Register in in-memory registry
    global_rule_registry.register(rule)

    await log_audit_event(
        db=db,
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        action="CREATE_DETECTION_RULE",
        resource_type="DETECTION_RULE",
        resource_id=rule.rule_id,
        result="SUCCESS",
        metadata={"name": rule.name, "severity": rule.severity},
    )

    await db.commit()
    await db.refresh(rule)
    return rule


@router.patch(
    "/{rule_id}",
    response_model=DetectionRuleRead,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            require_roles(
                [
                    Role.TENANT_ADMIN,
                    Role.SECURITY_ENGINEER,
                    Role.SECURITY_MANAGER,
                    Role.CISO,
                ]
            )
        )
    ],
)
async def update_rule(
    rule_id: str,
    rule_in: DetectionRuleUpdate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Updates a tenant-specific custom detection rule.
    Global baseline system rules cannot be directly modified.
    Enforces strict tenant boundary isolation.
    """
    stmt = select(DetectionRule).where(
        DetectionRule.rule_id == rule_id,
        or_(
            DetectionRule.tenant_id.is_(None),
            DetectionRule.tenant_id == ctx.tenant_id,
        ),
    )
    res = await db.execute(stmt)
    rule = res.scalars().first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found.",
        )

    if rule.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Global baseline system rules cannot be modified directly. Create a tenant-specific rule instead.",
        )

    if rule_in.name is not None:
        rule.name = rule_in.name
    if rule_in.description is not None:
        rule.description = rule_in.description
    if rule_in.version is not None:
        rule.version = rule_in.version
    if rule_in.enabled is not None:
        rule.enabled = rule_in.enabled
    if rule_in.severity is not None:
        rule.severity = rule_in.severity.upper()
    if rule_in.confidence is not None:
        rule.confidence = rule_in.confidence
    if rule_in.event_types is not None:
        rule.event_types = [t.upper() for t in rule_in.event_types]
    if rule_in.conditions is not None:
        rule.conditions = rule_in.conditions
    if rule_in.mitre_techniques is not None:
        for tech in rule_in.mitre_techniques:
            if not MitreAttackCatalog.validate_technique_id(tech):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid MITRE ATT&CK technique ID: '{tech}'.",
                )
        rule.mitre_techniques = rule_in.mitre_techniques
        rule.mitre_tactics = sorted(
            set((rule_in.mitre_tactics or []) + MitreAttackCatalog.resolve_tactics(rule_in.mitre_techniques))
        )
    elif rule_in.mitre_tactics is not None:
        rule.mitre_tactics = rule_in.mitre_tactics
    if rule_in.tags is not None:
        rule.tags = rule_in.tags

    rule.updated_at = datetime.now(UTC)
    global_rule_registry.register(rule)

    await log_audit_event(
        db=db,
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        action="UPDATE_DETECTION_RULE",
        resource_type="DETECTION_RULE",
        resource_id=rule.rule_id,
        result="SUCCESS",
        metadata={"name": rule.name, "enabled": rule.enabled},
    )

    await db.commit()
    await db.refresh(rule)
    return rule
