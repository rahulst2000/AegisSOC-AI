import re
import uuid
from typing import Any

from app.detection.mitre_mapper import MitreAttackCatalog
from app.detection.sigma_parser import extract_mitre_from_tags, parse_sigma_yaml


def parse_timeframe_to_minutes(tf_str: str | None) -> int:
    """Parses Sigma timeframe strings like '5m', '10m', '1h', '24h' into integer minutes."""
    if not tf_str:
        return 5  # default 5 minutes
    tf_str = tf_str.strip().lower()
    if tf_str.endswith("m"):
        return int(tf_str[:-1])
    elif tf_str.endswith("h"):
        return int(tf_str[:-1]) * 60
    elif tf_str.endswith("d"):
        return int(tf_str[:-1]) * 1440
    elif tf_str.isdigit():
        return int(tf_str)
    return 5


def parse_aggregation_expression(condition: str) -> dict[str, Any] | None:
    """
    Parses aggregation pipes from Sigma condition expressions.
    e.g. 'selection | count() > 10'
    e.g. 'selection | count(username) by source_ip > 5'
    """
    if "|" not in condition:
        return None

    pipe_parts = [p.strip() for p in condition.split("|")]
    agg_part = pipe_parts[-1]

    # Pattern: count([field]) [by group_field] [>|>=] [number]
    match = re.search(
        r"count\((?P<field>[a-zA-Z0-9_]*)\)(?:\s+by\s+(?P<by>[a-zA-Z0-9_]+))?\s*(?P<op>>=|>|==)\s*(?P<threshold>\d+)",
        agg_part,
    )
    if match:
        field = match.group("field") or None
        group_by = match.group("by") or None
        op = match.group("op")
        threshold = int(match.group("threshold"))
        return {
            "type": "count",
            "field": field,
            "group_by": group_by,
            "op": op,
            "threshold": threshold,
        }
    return None


def compile_sigma_rule(raw_yaml: str, tenant_id: uuid.UUID | None = None) -> dict[str, Any]:
    """
    Compiles a raw Sigma YAML rule into AegisSOC internal executable representation.
    Extracts MITRE techniques, logsource mappings, selection criteria, and aggregation rules.
    """
    parsed = parse_sigma_yaml(raw_yaml)

    detection = parsed["detection"]
    condition = detection.get("condition", "")
    timeframe = detection.get("timeframe")
    timeframe_minutes = parse_timeframe_to_minutes(timeframe)

    # Separate selections and filters from condition
    selections: dict[str, Any] = {}
    filters: dict[str, Any] = {}

    for k, v in detection.items():
        if k in {"condition", "timeframe"}:
            continue
        if k.startswith("filter"):
            filters[k] = v
        else:
            selections[k] = v

    # Extract tags & MITRE
    tags = parsed.get("tags", [])
    tactics, techniques = extract_mitre_from_tags(tags)

    # Validate techniques against catalog and backfill tactics
    validated_techniques = [t for t in techniques if MitreAttackCatalog.validate_technique_id(t)]
    backfilled_tactics = MitreAttackCatalog.resolve_tactics(validated_techniques)
    all_tactics = sorted(set(tactics + backfilled_tactics))

    # Derive target event types from logsource or selections
    event_types: set[str] = set()
    logsource = parsed.get("logsource", {})
    service = logsource.get("service", "").upper()
    category = logsource.get("category", "").upper()

    for item in selections.values():
        if isinstance(item, dict):
            if "event_type" in item:
                val = item["event_type"]
                if isinstance(val, list):
                    event_types.update([str(x).upper() for x in val])
                else:
                    event_types.add(str(val).upper())

    if not event_types:
        if service:
            event_types.add(f"{service}_EVENT")
        elif category:
            event_types.add(f"{category}_EVENT")
        else:
            event_types.add("SECURITY_EVENT")

    aggregation = parse_aggregation_expression(condition)

    compiled_rule = {
        "rule_id": str(parsed.get("id") or f"AEGIS-SIG-{uuid.uuid4().hex[:8].upper()}"),
        "tenant_id": tenant_id,
        "name": parsed.get("title", "Unnamed Detection Rule"),
        "description": parsed.get("description", "No description provided."),
        "version": str(parsed.get("version", "1.0.0")),
        "enabled": bool(parsed.get("status", "test") != "disabled"),
        "severity": parsed.get("level", "medium").upper(),
        "confidence": float(parsed.get("confidence", 0.9)),
        "event_types": sorted(event_types),
        "conditions": {
            "selections": selections,
            "filters": filters,
            "condition": condition,
            "timeframe_minutes": timeframe_minutes,
            "aggregation": aggregation,
        },
        "mitre_tactics": all_tactics,
        "mitre_techniques": validated_techniques,
        "tags": tags,
    }

    return compiled_rule


class SigmaCompiler:
    """Compiler interface for Sigma YAML detection rules."""

    @staticmethod
    def compile_rule_from_yaml(raw_yaml: str, tenant_id: uuid.UUID | None = None) -> dict[str, Any]:
        return compile_sigma_rule(raw_yaml, tenant_id)
