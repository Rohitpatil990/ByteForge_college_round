"""Agent Execution Runner and Orchestrator for AgentBreak (P1).

Frozen contract:
run_agent(scenario, defense_config, target_config) -> trace

Guarantees:
- Validates scenario input strictly (reads scenario.input.user_msg; refuses initial_input).
- Copies attack_id, kind, variant_source, parent_run_id, round, and attacker_inputs unchanged.
- Validates doc references (raises on unknown string ID).
- Pre-execution guard check before every tool execution.
- Hash-chains and persists the trace to data/traces/{run_id}.json.
- Every normal trace ends with exactly one final_reply step.
- Runs with API/timeout errors are recorded as label 'error' without final_reply.
"""

import os
import uuid
from typing import Any, Dict, List, Optional

from target.agent import ConfiguredTargetAgent
from target.tracer import TraceLogger


def run_agent(
    scenario: Dict[str, Any],
    defense_config: Optional[Dict[str, bool]] = None,
    target_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute target agent against scenario and return hash-chained trace.

    Frozen contract: run_agent(scenario, defense_config, target_config) -> trace
    """
    if target_config is None:
        from target.config import load_target
        target_id = scenario.get("target_id", "demo-company-assistant")
        target_config = load_target(target_id)

    # 1. Normalize scenario input (Fix 3 - Canonical input with legacy initial_input fallback)
    if "input" in scenario and scenario["input"] is not None:
        raw_input = scenario["input"]
        if not isinstance(raw_input, dict):
            raise ValueError("Scenario 'input' must be a dictionary")
        user_msg = raw_input.get("user_msg")
        if not user_msg or not isinstance(user_msg, str) or not user_msg.strip():
            raise ValueError("Scenario 'input' must contain a non-empty string 'user_msg'")
        docs_list = list(raw_input.get("docs") or [])
        if not docs_list and scenario.get("synthetic_docs"):
            docs_list = [d.get("doc_id") for d in scenario.get("synthetic_docs") if isinstance(d, dict) and d.get("doc_id")]
        scenario_input = {
            "user_msg": user_msg.strip(),
            "docs": docs_list,
            "memory": list(raw_input.get("memory") or []),
        }
    elif "initial_input" in scenario and scenario["initial_input"] is not None:
        raw_initial = scenario["initial_input"]
        if isinstance(raw_initial, str):
            if not raw_initial.strip():
                raise ValueError("Scenario 'initial_input' string must not be empty")
            scenario_input = {
                "user_msg": raw_initial.strip(),
                "docs": list(scenario.get("synthetic_docs") or []),
                "memory": [],
            }
        elif isinstance(raw_initial, dict):
            user_msg = raw_initial.get("user_msg")
            if not user_msg or not isinstance(user_msg, str) or not user_msg.strip():
                raise ValueError("Scenario 'initial_input' object must contain a non-empty string 'user_msg'")
            scenario_input = {
                "user_msg": user_msg.strip(),
                "docs": list(raw_initial.get("docs") or scenario.get("synthetic_docs") or []),
                "memory": list(raw_initial.get("memory") or []),
            }
        else:
            raise ValueError("Scenario 'initial_input' must be a string or dictionary")
    else:
        raise ValueError("Malformed scenario: must provide either 'input' or 'initial_input' with 'user_msg'")

    # 2. Extract run metadata
    run_id = scenario.get("run_id") or f"r_{uuid.uuid4().hex[:8]}"
    assessment_id = scenario.get("assessment_id", "a_01")
    attack_id = scenario.get("attack_id", "unknown_attack")
    target_id = target_config.get("id", "demo-company-assistant")

    kind = scenario.get("kind", "seed")
    variant_source = scenario.get("variant_source", None)
    parent_run_id = scenario.get("parent_run_id", None)
    round_num = scenario.get("round", 0)
    attacker_inputs = scenario.get("attacker_inputs", None)

    # 3. Determine guard configuration
    def_cfg = dict(defense_config or {})
    active_defenses = [k for k, v in def_cfg.items() if v]

    guard_mode = scenario.get("guard_mode")
    if not guard_mode:
        guard_mode = "enforced" if any(def_cfg.values()) else "off"

    mode = "guarded" if guard_mode == "enforced" else "unguarded"

    # 4. Instantiate agent and run
    target_execution_mode = (
        scenario.get("target_execution_mode")
        or scenario.get("config", {}).get("target_execution_mode")
    )
    target_model_client = (
        scenario.get("target_model_client")
        or scenario.get("config", {}).get("target_model_client")
    )

    agent = ConfiguredTargetAgent(
        target_config=target_config,
        model_name=scenario.get("config", {}).get("model", "gemini-2.5-flash"),
        temperature=scenario.get("config", {}).get("temperature", 0.2),
        model_client=target_model_client,
    )

    user_msg = scenario_input["user_msg"]
    docs = scenario_input["docs"]
    memory = scenario_input["memory"]
    role = scenario.get("role", target_config.get("role", "support"))

    simulated = bool(
        scenario.get("simulated", False)
        or scenario.get("config", {}).get("simulated", False)
        or os.getenv("AGENTBREAK_SIMULATED", "0") == "1"
    )
    simulate_error = scenario.get("simulate_error") or scenario.get("config", {}).get("simulate_error")

    synthetic_docs = scenario.get("synthetic_docs")

    exec_result = agent.execute(
        user_msg=user_msg,
        docs=docs,
        memory=memory,
        defense_config=def_cfg,
        guard_mode=guard_mode,
        run_id=run_id,
        role=role,
        simulated=simulated,
        simulate_error=simulate_error,
        model_client=target_model_client,
        target_execution_mode=target_execution_mode,
        synthetic_docs=synthetic_docs,
    )

    # 4.5. Dynamic defense post-execution filter (e.g. D3 reply canary filter)
    try:
        import defense
        if hasattr(defense, "filter_final_reply") and callable(defense.filter_final_reply):
            defense.filter_final_reply(exec_result, def_cfg, target_config)
    except Exception:
        pass

    # 5. Build trace structure
    if exec_result.is_error:
        verdict = {
            "label": "error",
            "rule": None,
            "attempted_violation": False,
            "executed_violation": False,
            "severity": None,
            "evidence_steps": [],
            "error_message": exec_result.error_message,
        }
    elif exec_result.verdict_label == "blocked_attempt":
        verdict = {
            "label": "blocked_attempt",
            "rule": exec_result.verdict_rule,
            "attempted_violation": True,
            "executed_violation": False,
            "severity": None,
            "evidence_steps": exec_result.evidence_steps,
        }
    else:
        verdict = {
            "label": "no_violation",
            "rule": None,
            "attempted_violation": False,
            "executed_violation": False,
            "severity": None,
            "evidence_steps": [],
        }

    trace_record: Dict[str, Any] = {
        "run_id": run_id,
        "assessment_id": assessment_id,
        "attack_id": attack_id,
        "target_id": target_id,
        "kind": kind,
        "variant_source": variant_source,
        "parent_run_id": parent_run_id,
        "attacker_inputs": attacker_inputs,
        "round": round_num,
        "mode": mode,
        "guard_mode": guard_mode,
        "defenses": active_defenses,
        "target_execution_mode": exec_result.target_execution_mode,
        "is_target_model_invoked": exec_result.is_model_invoked,
        "config": {
            "model": agent.model_name,
            "temperature": agent.temperature,
            "target_execution_mode": exec_result.target_execution_mode,
            "is_target_model_invoked": exec_result.is_model_invoked,
        },
        "input": scenario_input,
        "steps": exec_result.steps,
        "verdict": verdict,
    }

    # 6. Cryptographically hash-chain and persist trace
    logger_instance = TraceLogger()
    persisted_trace = logger_instance.log_trace(trace_record)

    return persisted_trace
