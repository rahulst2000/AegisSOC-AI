import logging
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.detection.models import DetectionRule
from app.detection.registry import global_rule_registry
from app.detection.sigma_compiler import compile_sigma_rule
from app.detection.sigma_parser import SigmaParseError

logger = logging.getLogger(__name__)


def create_rule_model_from_compiled(compiled: dict[str, Any], tenant_id: uuid.UUID | None = None) -> DetectionRule:
    """Instantiates a DetectionRule model from compiled dictionary specification."""
    return DetectionRule(
        rule_id=compiled["rule_id"],
        tenant_id=tenant_id or compiled.get("tenant_id"),
        name=compiled["name"],
        description=compiled["description"],
        version=compiled.get("version", "1.0.0"),
        enabled=compiled.get("enabled", True),
        severity=compiled.get("severity", "MEDIUM"),
        confidence=compiled.get("confidence", 0.9),
        event_types=compiled.get("event_types", []),
        conditions=compiled.get("conditions", {}),
        mitre_tactics=compiled.get("mitre_tactics", []),
        mitre_techniques=compiled.get("mitre_techniques", []),
        tags=compiled.get("tags", []),
    )


def load_rule_from_yaml_content(content: str, tenant_id: uuid.UUID | None = None) -> DetectionRule:
    """Parses, compiles, and instantiates a DetectionRule from raw YAML text."""
    compiled = compile_sigma_rule(content, tenant_id=tenant_id)
    return create_rule_model_from_compiled(compiled, tenant_id=tenant_id)


def load_rules_from_directory(
    dir_path: Path | str = "detection_rules",
    tenant_id: uuid.UUID | None = None,
) -> list[DetectionRule]:
    """
    Reads all .yml and .yaml files in dir_path, compiles them safely,
    and returns a list of DetectionRule instances.
    Skips invalid or oversized files without raising to prevent denial of service.
    """
    directory = Path(dir_path)
    if not directory.exists():
        # Try relative to repo root if run from backend folder
        candidate = Path("..") / dir_path
        if candidate.exists():
            directory = candidate
        else:
            # Try absolute from file location
            repo_root = Path(__file__).resolve().parents[3]
            candidate_repo = repo_root / "detection_rules"
            if candidate_repo.exists():
                directory = candidate_repo
            else:
                candidate_app = Path(__file__).resolve().parents[2] / "detection_rules"
                if candidate_app.exists():
                    directory = candidate_app

    if not directory.exists() or not directory.is_dir():
        logger.warning(f"Detection rules directory not found: {directory}")
        return []

    rules: list[DetectionRule] = []
    yaml_files = sorted(list(directory.glob("*.yml")) + list(directory.glob("*.yaml")))

    for rule_file in yaml_files:
        try:
            content = rule_file.read_text(encoding="utf-8")
            rule = load_rule_from_yaml_content(content, tenant_id=tenant_id)
            rules.append(rule)
            logger.info(f"Loaded detection rule '{rule.name}' ({rule.rule_id}) from {rule_file.name}")
        except SigmaParseError as exc:
            logger.error(f"Failed to parse rule file {rule_file.name}: {exc}")
        except Exception as exc:
            logger.error(f"Unexpected error loading rule file {rule_file.name}: {exc}", exc_info=True)

    return rules


async def sync_rules_to_db(
    db: AsyncSession,
    dir_path: Path | str = "detection_rules",
) -> list[DetectionRule]:
    """
    Loads rules from disk and synchronizes them into the database as global baseline rules.
    Populates global_rule_registry for fast in-memory execution.
    """
    disk_rules = load_rules_from_directory(dir_path, tenant_id=None)
    synced_rules: list[DetectionRule] = []

    for disk_rule in disk_rules:
        # Check if rule already exists in DB
        stmt = select(DetectionRule).where(
            DetectionRule.rule_id == disk_rule.rule_id,
            DetectionRule.tenant_id.is_(None),
        )
        result = await db.execute(stmt)
        existing_rule = result.scalars().first()

        if existing_rule:
            existing_rule.name = disk_rule.name
            existing_rule.description = disk_rule.description
            existing_rule.version = disk_rule.version
            existing_rule.enabled = disk_rule.enabled
            existing_rule.severity = disk_rule.severity
            existing_rule.confidence = disk_rule.confidence
            existing_rule.event_types = disk_rule.event_types
            existing_rule.conditions = disk_rule.conditions
            existing_rule.mitre_tactics = disk_rule.mitre_tactics
            existing_rule.mitre_techniques = disk_rule.mitre_techniques
            existing_rule.tags = disk_rule.tags
            target_rule = existing_rule
        else:
            db.add(disk_rule)
            target_rule = disk_rule

        synced_rules.append(target_rule)
        global_rule_registry.register(target_rule)

    await db.commit()
    for rule in synced_rules:
        await db.refresh(rule)

    return synced_rules
