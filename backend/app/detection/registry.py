import uuid

from app.detection.models import DetectionRule


class RuleRegistry:
    """
    In-memory registry of active detection rules.
    Maintains fast lookup structures for global system rules and tenant-specific rules.
    """

    def __init__(self) -> None:
        # Key: rule_id -> DetectionRule
        self._rules: dict[str, DetectionRule] = {}

    def register(self, rule: DetectionRule) -> None:
        """Register or update an active detection rule."""
        self._rules[rule.rule_id] = rule

    def unregister(self, rule_id: str) -> bool:
        """Remove a rule by ID."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False

    def get_rule(self, rule_id: str) -> DetectionRule | None:
        """Retrieve a rule by ID."""
        return self._rules.get(rule_id)

    def get_all_rules(self) -> list[DetectionRule]:
        """Return all registered rules."""
        return list(self._rules.values())

    def get_rules_for_tenant(self, tenant_id: uuid.UUID | None) -> list[DetectionRule]:
        """
        Return all rules applicable to a given tenant:
        - All global rules (tenant_id is None)
        - Tenant-specific rules matching tenant_id (if tenant_id provided)
        Never return another tenant's rules.
        """
        applicable: list[DetectionRule] = []
        for rule in self._rules.values():
            if not rule.enabled:
                continue
            if rule.tenant_id is None:
                # Global rule
                applicable.append(rule)
            elif tenant_id is not None and rule.tenant_id == tenant_id:
                # Matching tenant rule
                applicable.append(rule)
        return applicable

    def clear(self) -> None:
        """Clear all cached rules."""
        self._rules.clear()

    def count(self) -> int:
        """Return number of registered rules."""
        return len(self._rules)


# Global registry singleton
global_rule_registry = RuleRegistry()
