"""Target Configuration Loader and Validator for AgentBreak (P1).

Loads and strictly validates target agent configuration YAML files.
In accordance with Fix 3 (Configurable Target):
- Target agent instructions, tools, mock mappings, synthetic data,
  canary secrets, policy, and legitimate tasks live strictly in configuration.
- No module hardcodes prompt text, tool names, email domains, or canary strings.
- Refuses incomplete or malformed target configurations with clear messages.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

# Resolve project root and default target configurations directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIGS_DIR = PROJECT_ROOT / "target" / "configs"

REQUIRED_CONFIG_SECTIONS: Set[str] = {
    "id",
    "name",
    "system_prompt",
    "tools",
    "mock_behavior",
    "data",
    "canary_secrets",
    "policy",
    "legit_tasks",
}


def get_configs_dir(custom_dir: Optional[Path] = None) -> Path:
    """Return the absolute path to the target configs directory."""
    if custom_dir:
        return custom_dir if custom_dir.is_absolute() else PROJECT_ROOT / custom_dir
    env_dir = os.getenv("TARGET_CONFIGS_DIR")
    if env_dir:
        candidate = Path(env_dir)
        return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate
    return DEFAULT_CONFIGS_DIR


def validate_target_config(data: Any) -> Tuple[bool, Optional[str]]:
    """Validate a target configuration dictionary against the frozen v2 requirements.

    Validation rules:
    1. Must be a valid dictionary structure.
    2. All required top-level sections must be present:
       - id, name, system_prompt, tools, mock_behavior, data, canary_secrets, policy, legit_tasks.
    3. Every tool listed in 'tools' must have an entry in 'mock_behavior'.
    4. At least one canary secret must be defined in 'canary_secrets'.
    5. Returns (True, None) if valid, or (False, error_message) if invalid.
    """
    if not isinstance(data, dict):
        return False, "Target configuration must be a dictionary/mapping"

    # Check required top-level sections
    missing_sections = sorted([sec for sec in REQUIRED_CONFIG_SECTIONS if sec not in data])
    if missing_sections:
        return (
            False,
            f"Missing required target configuration section(s): {', '.join(missing_sections)}",
        )

    # Validate id and name
    target_id = data.get("id")
    if not isinstance(target_id, str) or not target_id.strip():
        return False, "Target configuration 'id' must be a non-empty string"

    target_name = data.get("name")
    if not isinstance(target_name, str) or not target_name.strip():
        return False, "Target configuration 'name' must be a non-empty string"

    # Validate system prompt
    system_prompt = data.get("system_prompt")
    if not isinstance(system_prompt, str) or not system_prompt.strip():
        return False, "Target configuration 'system_prompt' must be a non-empty string"

    # Validate tools
    tools = data.get("tools")
    if not isinstance(tools, list) or len(tools) == 0:
        return False, "Target configuration 'tools' must be a non-empty list"

    # Validate mock_behavior
    mock_behavior = data.get("mock_behavior")
    if not isinstance(mock_behavior, dict):
        return False, "Target configuration 'mock_behavior' must be a mapping of tool -> mock function"

    # Ensure every tool has a configured mock behavior
    missing_mocks = []
    for tool_entry in tools:
        if not isinstance(tool_entry, dict) or "name" not in tool_entry:
            return False, "Each entry in 'tools' must be a dictionary with a 'name' field"
        tname = tool_entry["name"]
        if tname not in mock_behavior or not mock_behavior[tname]:
            missing_mocks.append(tname)

    if missing_mocks:
        return (
            False,
            f"Tools missing mock behavior mapping: {', '.join(missing_mocks)}",
        )

    # Validate canary_secrets
    canary_secrets = data.get("canary_secrets")
    if not isinstance(canary_secrets, list) or len(canary_secrets) == 0:
        return False, "Target configuration 'canary_secrets' must define at least one canary string"

    for canary in canary_secrets:
        if not isinstance(canary, str) or not canary.strip():
            return False, "Canary secrets must contain non-empty string tokens"

    # Validate data section
    data_section = data.get("data")
    if not isinstance(data_section, dict):
        return False, "Target configuration 'data' must be a dictionary of synthetic data (docs, kb, records)"

    # Validate policy section
    policy_section = data.get("policy")
    if not isinstance(policy_section, dict):
        return False, "Target configuration 'policy' must be a dictionary of security policy rules"

    # Validate legit_tasks
    legit_tasks = data.get("legit_tasks")
    if not isinstance(legit_tasks, list) or len(legit_tasks) == 0:
        return False, "Target configuration 'legit_tasks' must define at least one benign evaluation task"

    return True, None


def load_target(target_id: str, configs_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Load and validate a target configuration by ID.

    Frozen contract: load_target(target_id) -> target_config
    Loads and strictly VALIDATES the config. Refuses invalid configurations with ValueError.

    Raises:
        FileNotFoundError: If no configuration file matching target_id is found.
        ValueError: If configuration fails validation checks.
    """
    directory = get_configs_dir(configs_dir)
    if not directory.exists() or not directory.is_dir():
        raise FileNotFoundError(f"Target configurations directory not found: {directory}")

    # Search for matching yaml/yml file
    target_file = None
    for ext in (".yaml", ".yml"):
        candidate = directory / f"{target_id}{ext}"
        if candidate.exists():
            target_file = candidate
            break

    if target_file is None:
        # Search all yaml files inside directory in case target_id doesn't match filename
        for candidate in directory.glob("*.y*ml"):
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    parsed = yaml.safe_load(f)
                    if isinstance(parsed, dict) and parsed.get("id") == target_id:
                        target_file = candidate
                        break
            except Exception:
                continue

    if target_file is None:
        raise FileNotFoundError(f"Target configuration '{target_id}' not found in {directory}")

    with open(target_file, "r", encoding="utf-8") as f:
        try:
            config_data = yaml.safe_load(f)
        except Exception as exc:
            raise ValueError(f"Failed to parse target YAML file '{target_file.name}': {exc}") from exc

    is_valid, validation_error = validate_target_config(config_data)
    if not is_valid:
        raise ValueError(
            f"Target configuration '{target_id}' refused by loader: {validation_error}"
        )

    return config_data


def list_target_configs(configs_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """List all target configurations in the configs directory with validation status.

    Returns:
        List of dicts: [{"id": ..., "name": ..., "valid": bool, "validation_error": Optional[str]}]
    """
    directory = get_configs_dir(configs_dir)
    results: List[Dict[str, Any]] = []

    if not directory.exists() or not directory.is_dir():
        return results

    yaml_files = sorted(
        list(directory.glob("*.yaml")) + list(directory.glob("*.yml")),
        key=lambda p: p.name,
    )

    for file_path in yaml_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as exc:
            results.append({
                "id": file_path.stem,
                "name": file_path.stem,
                "valid": False,
                "validation_error": f"Failed to parse YAML file '{file_path.name}': {exc}",
            })
            continue

        if not isinstance(data, dict):
            results.append({
                "id": file_path.stem,
                "name": file_path.stem,
                "valid": False,
                "validation_error": f"Invalid YAML root in '{file_path.name}': expected dictionary",
            })
            continue

        target_id = data.get("id", file_path.stem)
        target_name = data.get("name", file_path.stem)

        is_valid, validation_error = validate_target_config(data)

        results.append({
            "id": target_id,
            "name": target_name,
            "valid": is_valid,
            "validation_error": validation_error,
        })

    return results
