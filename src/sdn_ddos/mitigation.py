from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


@dataclass
class MitigationRule:
    rule_id: str
    src_ip: str | None = None
    src_prefix: str | None = None
    action: str = "rate_limit"
    rate_limit_pps: int = 25
    expires_at: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "src_ip": self.src_ip,
            "src_prefix": self.src_prefix,
            "action": self.action,
            "rate_limit_pps": self.rate_limit_pps,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
        }


class MitigationManager:
    """Tracks and expires temporary rules.

    The class is deliberately infrastructure-independent: the rule set mirrors the
    state an OpenFlow controller would maintain before pushing flow mods to the
    switch.
    """

    def __init__(self, rule_ttl_seconds: int = 30, max_rules: int = 25):
        self.rule_ttl_seconds = rule_ttl_seconds
        self.max_rules = max_rules
        self.rules: Dict[str, MitigationRule] = {}

    def add_rule(self, *, src_ip: str | None = None, src_prefix: str | None = None, action: str = "rate_limit", rate_limit_pps: int = 25) -> MitigationRule:
        if len(self.rules) >= self.max_rules:
            self.expire_rules()
        rule_id = f"rule-{len(self.rules) + 1}"
        rule = MitigationRule(
            rule_id=rule_id,
            src_ip=src_ip,
            src_prefix=src_prefix,
            action=action,
            rate_limit_pps=rate_limit_pps,
            expires_at=(datetime.now(timezone.utc).timestamp() + self.rule_ttl_seconds),
        )
        self.rules[rule_id] = rule
        return rule

    def expire_rules(self) -> List[dict[str, Any]]:
        expired = []
        for rule_id, rule in list(self.rules.items()):
            if rule.expires_at is not None and float(rule.expires_at) <= datetime.now(timezone.utc).timestamp():
                self.rules.pop(rule_id)
                expired.append({"rule_id": rule_id, "status": "expired"})
        return expired

    def clear(self) -> None:
        self.rules.clear()

    def list_rules(self) -> List[dict[str, Any]]:
        return [rule.as_dict() for rule in self.rules.values()]
