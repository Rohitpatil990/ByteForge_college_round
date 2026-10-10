"""AgentBreak Analyzer Package.

Owned by P2 (Attacker & Analyzer).
Evaluates execution traces against frozen analyzer rule IDs:
- canary_in_executed_args (critical)
- canary_in_final_reply (critical)
- executed_outside_policy (high)
- memory_write_untrusted (medium)
"""

from analyzer.core import (
    RULE_SEVERITY_MAP,
    analyze,
    map_finding_source,
    persist_finding,
)
from analyzer.rules import (
    contains_canary,
    extract_canaries,
    normalize_text,
)

__all__ = [
    "analyze",
    "extract_canaries",
    "normalize_text",
    "contains_canary",
    "map_finding_source",
    "persist_finding",
    "RULE_SEVERITY_MAP",
]
