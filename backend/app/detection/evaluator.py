import re
from typing import Any

from app.models.event import SecurityEvent


def extract_field_value(event: SecurityEvent, field_path: str) -> Any:
    """
    Extracts a field from a SecurityEvent, searching top-level attributes,
    normalized_event dictionary, and raw_event dictionary.
    """
    field_lower = field_path.lower()

    # 1. Direct top-level attributes
    if hasattr(event, field_lower):
        val = getattr(event, field_lower)
        if val is not None:
            return val

    # 2. Check normalized_event
    if isinstance(event.normalized_event, dict):
        if field_path in event.normalized_event:
            return event.normalized_event[field_path]
        # Check nested dotted paths e.g. 'source.ip'
        if "." in field_path:
            parts = field_path.split(".")
            curr = event.normalized_event
            for p in parts:
                if isinstance(curr, dict) and p in curr:
                    curr = curr[p]
                else:
                    curr = None
                    break
            if curr is not None:
                return curr

    # 3. Check raw_event
    if isinstance(event.raw_event, dict):
        if field_path in event.raw_event:
            return event.raw_event[field_path]
        for k, v in event.raw_event.items():
            if k.lower() == field_lower:
                return v

    return None


def match_field_value(actual: Any, target: Any, modifier: str | None = None) -> bool:
    """
    Controlled safe value evaluation without code execution or eval().
    Supports equality, lists (OR), substrings (contains), prefixes, and regex.
    """
    if actual is None:
        return target is None or target == ""

    # If target is a list, match any item (logical OR)
    if isinstance(target, list):
        return any(match_field_value(actual, item, modifier) for item in target)

    actual_str = str(actual).strip()
    target_str = str(target).strip()

    if modifier == "contains":
        return target_str.lower() in actual_str.lower()
    elif modifier == "startswith":
        return actual_str.lower().startswith(target_str.lower())
    elif modifier == "endswith":
        return actual_str.lower().endswith(target_str.lower())
    elif modifier == "re":
        try:
            return bool(re.search(target_str, actual_str, re.IGNORECASE))
        except re.error:
            return False
    else:
        # Default exact match (case-insensitive for strings)
        return actual_str.lower() == target_str.lower()


def evaluate_selection(event: SecurityEvent, selection_dict: dict[str, Any]) -> bool:
    """
    Evaluates whether an event satisfies all criteria in a selection dictionary.
    """
    if not isinstance(selection_dict, dict):
        return False

    for field_spec, target_val in selection_dict.items():
        # Handle field modifiers e.g. 'Image|endswith' or 'CommandLine|contains'
        modifier = None
        field_name = field_spec
        if "|" in field_spec:
            parts = field_spec.split("|")
            field_name = parts[0]
            modifier = parts[1].lower()

        actual_val = extract_field_value(event, field_name)
        if not match_field_value(actual_val, target_val, modifier):
            return False

    return True


def evaluate_rule_against_events(
    rule_conditions: dict[str, Any],
    events: list[SecurityEvent],
) -> list[SecurityEvent]:
    """
    Evaluates rule conditions across a candidate sequence of events.
    Returns the list of matching SecurityEvents that constitute verifiable evidence.
    If conditions are not met, returns an empty list.
    """
    if not events:
        return []

    selections = rule_conditions.get("selections", {})
    filters = rule_conditions.get("filters", {})
    aggregation = rule_conditions.get("aggregation")

    # Step 1: Filter events matching the selection criteria and not matching filters
    matched_events: list[SecurityEvent] = []
    for evt in events:
        # Any selection match
        matches_any_selection = False
        if not selections:
            matches_any_selection = True
        else:
            for sel_dict in selections.values():
                if isinstance(sel_dict, dict) and evaluate_selection(evt, sel_dict):
                    matches_any_selection = True
                    break

        if not matches_any_selection:
            continue

        # Check exclusion filters
        excluded = False
        for flt_dict in filters.values():
            if isinstance(flt_dict, dict) and evaluate_selection(evt, flt_dict):
                excluded = True
                break

        if not excluded:
            matched_events.append(evt)

    if not matched_events:
        return []

    # Step 2: Handle aggregation criteria if present (e.g. threshold > 10 in window)
    if aggregation:
        group_by = aggregation.get("group_by")
        field = aggregation.get("field")
        op = aggregation.get("op", ">=")
        threshold = aggregation.get("threshold", 1)

        if group_by:
            # Group matched events by group_by field (e.g. source_ip)
            groups: dict[Any, list[SecurityEvent]] = {}
            for e in matched_events:
                key = extract_field_value(e, group_by)
                if key:
                    groups.setdefault(key, []).append(e)

            # Find groups meeting threshold
            qualifying_events: list[SecurityEvent] = []
            for _group_key, grp_events in groups.items():
                count_val = len(grp_events)
                if field:
                    # Count distinct values of field
                    distinct_vals = {extract_field_value(ge, field) for ge in grp_events}
                    distinct_vals.discard(None)
                    count_val = len(distinct_vals)

                is_met = False
                if op == ">" and count_val > threshold:
                    is_met = True
                elif op in {">=", "=="} and count_val >= threshold:
                    is_met = True

                if is_met:
                    qualifying_events.extend(grp_events)

            return qualifying_events
        else:
            count_val = len(matched_events)
            is_met = False
            if op == ">" and count_val > threshold:
                is_met = True
            elif op in {">=", "=="} and count_val >= threshold:
                is_met = True

            return matched_events if is_met else []

    # Non-aggregation rule: every matched event qualifies
    return matched_events
