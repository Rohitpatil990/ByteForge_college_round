"""AgentBreak API Routes.

Implements shared endpoints:
- GET /health
- GET /target/configs
- POST /assessments/{id}/target
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from fastapi import APIRouter, HTTPException, Path as PathParam
from pydantic import BaseModel, Field

router = APIRouter()

# Resolve project root and target configs directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIGS_DIR = PROJECT_ROOT / "target" / "configs"


def get_configs_dir() -> Path:
    env_dir = os.getenv("TARGET_CONFIGS_DIR")
    if env_dir:
        candidate = Path(env_dir)
        return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate
    return DEFAULT_CONFIGS_DIR


class TargetConfigSummary(BaseModel):
    id: str
    name: str
    valid: bool
    validation_error: Optional[str] = None


class TargetSelectionRequest(BaseModel):
    target_id: str = Field(..., description="The ID of the target configuration to select")


class TargetSelectionResponse(BaseModel):
    assessment_id: str
    target_id: str
    target_name: Optional[str]
    status: str
    message: str


def load_target_configs(configs_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Scan and validate target configurations from YAML files in the configs directory.

    Returns a list of dicts with keys: id, name, valid, validation_error.
    Gracefully handles malformed YAML and missing required fields without crashing.
    """
    directory = configs_dir or get_configs_dir()
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
                "validation_error": f"Invalid YAML root structure in '{file_path.name}': expected dictionary/mapping",
            })
            continue

        target_id = data.get("id")
        target_name = data.get("name")

        if not target_id or not isinstance(target_id, str) or not target_id.strip():
            results.append({
                "id": file_path.stem,
                "name": target_name if isinstance(target_name, str) else file_path.stem,
                "valid": False,
                "validation_error": f"Missing or empty required field 'id' in '{file_path.name}'",
            })
            continue

        if not target_name or not isinstance(target_name, str) or not target_name.strip():
            results.append({
                "id": target_id,
                "name": file_path.stem,
                "valid": False,
                "validation_error": f"Missing or empty required field 'name' in '{file_path.name}'",
            })
            continue

        # Validate basic schema fields
        validation_error: Optional[str] = None
        if "role" not in data or not isinstance(data["role"], str):
            validation_error = "Missing or invalid 'role' field"
        elif "policy_ref" not in data or not isinstance(data["policy_ref"], str):
            validation_error = "Missing or invalid 'policy_ref' field"
        elif "tools" not in data or not isinstance(data["tools"], list):
            validation_error = "Missing or invalid 'tools' list"

        results.append({
            "id": target_id,
            "name": target_name,
            "valid": validation_error is None,
            "validation_error": validation_error,
        })

    return results


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@router.get("/health", summary="Health check")
def get_health() -> Dict[str, str]:
    """Return API health status."""
    return {
        "status": "ok",
        "service": "AgentBreak API",
        "version": "0.1.0",
    }


@router.get("/target/configs", response_model=List[TargetConfigSummary], summary="List target configurations")
def list_target_configs() -> List[Dict[str, Any]]:
    """List all available target configurations and their validation status."""
    return load_target_configs()


@router.post(
    "/assessments/{assessment_id}/target",
    response_model=TargetSelectionResponse,
    summary="Select target for an assessment",
)
def select_assessment_target(
    assessment_id: str = PathParam(..., description="Assessment identifier"),
    request: TargetSelectionRequest = ...,
) -> TargetSelectionResponse:
    """Select a target configuration for an assessment run.

    Validates that the requested target exists and is valid.
    Integration note: Returns target selection confirmation. Full assessment orchestration
    requires P1 (sandbox), P2 (attacker/analyzer), and P3 (defense/eval) integration.
    """
    configs = load_target_configs()
    matching = [cfg for cfg in configs if cfg["id"] == request.target_id]

    if not matching:
        raise HTTPException(
            status_code=404,
            detail=f"Target configuration '{request.target_id}' not found.",
        )

    target = matching[0]
    if not target["valid"]:
        raise HTTPException(
            status_code=400,
            detail=f"Target configuration '{request.target_id}' is invalid: {target['validation_error']}",
        )

    return TargetSelectionResponse(
        assessment_id=assessment_id,
        target_id=target["id"],
        target_name=target["name"],
        status="target_selected",
        message=(
            "Target selected. Agent sandbox (P1), attacker/analyzer (P2), and "
            "defense/eval (P3) are pending integration."
        ),
    )
