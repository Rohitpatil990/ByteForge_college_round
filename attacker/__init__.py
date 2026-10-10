"""AgentBreak Attacker Package.

Owned by P2 (Attacker & Analyzer).
Provides attack generators, adaptive strategies, and prompt mutation techniques:
- next_variant: Adaptive attack generator (Stage 3 & Stage 7)
- get_seed_scenarios: 4 standard synthetic seed attack scenarios
- get_seed_scenario_by_id: Retrieve seed attack by identifier
"""

from attacker.adaptive import (
    AttackerAuthenticationError,
    AttackerError,
    AttackerMaxRoundsError,
    AttackerModelError,
    AttackerRateLimitError,
    build_attacker_prompt,
    next_variant,
)
from attacker.seed_scenarios import (
    AttackScenario,
    get_seed_scenario_by_id,
    get_seed_scenarios,
)

__all__ = [
    "next_variant",
    "get_seed_scenarios",
    "get_seed_scenario_by_id",
    "build_attacker_prompt",
    "AttackScenario",
    "AttackerError",
    "AttackerAuthenticationError",
    "AttackerRateLimitError",
    "AttackerModelError",
    "AttackerMaxRoundsError",
]
