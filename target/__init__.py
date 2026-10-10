"""AgentBreak Target Package (P1 Sandbox & Traces).

Public exports for P2, P3, and P4:
- load_target(target_id) -> target_config
- list_target_configs() -> list of available configurations and validity
- validate_target_config(config_dict) -> (is_valid, error_msg)
- run_agent(scenario, defense_config, target_config) -> trace
- verify_trace_chain(traces_dir) -> verification results
- MockToolSandbox: mock tools execution environment
- GuardContext, check_guard: frozen guard interface
"""

from target.config import list_target_configs, load_target, validate_target_config
from target.guard import GuardContext, check_guard
from target.runner import run_agent
from target.tools import MockToolSandbox
from target.tracer import TraceLogger, canonical_json, compute_trace_hash, verify_trace_chain

__all__ = [
    "load_target",
    "list_target_configs",
    "validate_target_config",
    "run_agent",
    "verify_trace_chain",
    "TraceLogger",
    "compute_trace_hash",
    "canonical_json",
    "MockToolSandbox",
    "GuardContext",
    "check_guard",
]
