"""AgentBreak API Routes.

Implements all frozen P0 endpoints:
- GET /health
- GET /target/configs
- POST /assessments
- GET /assessments
- GET /assessments/{id}
- POST /assessments/{id}/target
- POST /assessments/{id}/runs
- GET /assessments/{id}/runs
- GET /runs/{run_id}
- GET /assessments/{id}/runs/{run_id}
- GET /assessments/{id}/findings
- GET /findings
- GET /defenses
- GET /assessments/{id}/defenses
- POST /defenses/{defense_id}/toggle
- POST /assessments/{id}/defenses/{defense_id}/toggle
- POST /assessments/{id}/challenge
- POST /assessments/{id}/retest
- GET /assessments/{id}/report
- POST /assessments/{id}/verify-chain
- POST /assessments/{id}/tamper-test
- GET /recorded/runs
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from fastapi import APIRouter, HTTPException, Path as PathParam, Query
from pydantic import BaseModel, Field

from api.store import (
    RECORDED_DATA_PATH,
    STORE,
    apply_defense_candidate_for_assessment,
    build_assessment_report,
    execute_adaptive_challenge,
    execute_adaptive_red_team_loop,
    execute_evolution_cycle,
    execute_retest,
    execute_seed_runs,
    get_defense_candidates_for_assessment,
    get_defense_history_for_assessment,
    rollback_defense_for_assessment,
    run_tamper_demonstration,
    verify_evidence_chain,
)

router = APIRouter()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIGS_DIR = PROJECT_ROOT / "target" / "configs"


def get_configs_dir() -> Path:
    env_dir = os.getenv("TARGET_CONFIGS_DIR")
    if env_dir:
        candidate = Path(env_dir)
        return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate
    return DEFAULT_CONFIGS_DIR


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

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


class CreateAssessmentRequest(BaseModel):
    name: Optional[str] = Field(None, description="Optional friendly assessment name")
    target_id: Optional[str] = Field(None, description="Optional target ID to pre-select")


class AssessmentSummary(BaseModel):
    id: str
    name: str
    target_id: Optional[str] = None
    target_name: Optional[str] = None
    status: str
    created_at: str
    updated_at: str
    runs_count: int
    findings_count: int


# ---------------------------------------------------------------------------
# Target Config Loader
# ---------------------------------------------------------------------------

def load_target_configs(configs_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Scan and validate target configurations from YAML files in the configs directory.

    Shows demo-company-assistant first.
    Marks target selectable only if validation succeeds.
    Returns real validation error when invalid.
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

        # Validate required schema fields
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

    # Ensure demo-company-assistant is shown first
    results.sort(key=lambda c: 0 if c["id"] == "demo-company-assistant" else 1)
    return results


# ---------------------------------------------------------------------------
# 1. Health & Configs
# ---------------------------------------------------------------------------

@router.get("/health", summary="Health check")
def get_health() -> Dict[str, Any]:
    """Return API health and system readiness."""
    return {
        "status": "ok",
        "service": "AgentBreak API",
        "version": "0.1.0",
        "framework": "FastAPI",
        "contract": "v2 frozen",
    }


@router.get("/target/configs", response_model=List[TargetConfigSummary], summary="List target configurations")
def list_target_configs() -> List[Dict[str, Any]]:
    """List all available target configurations and their validation status."""
    return load_target_configs()


# ---------------------------------------------------------------------------
# 2. Assessment Management
# ---------------------------------------------------------------------------

@router.post("/assessments", summary="Create new assessment")
def create_assessment(request: Optional[CreateAssessmentRequest] = None) -> Dict[str, Any]:
    """Create a new security assessment instance."""
    name = request.name if request else None
    target_id = request.target_id if request else None

    # If target_id provided, validate it first
    target_name = None
    if target_id:
        configs = load_target_configs()
        matching = [c for c in configs if c["id"] == target_id]
        if not matching:
            raise HTTPException(status_code=404, detail=f"Target configuration '{target_id}' not found.")
        if not matching[0]["valid"]:
            raise HTTPException(
                status_code=400,
                detail=f"Target configuration '{target_id}' is invalid: {matching[0]['validation_error']}",
            )
        target_name = matching[0]["name"]

    asmt = STORE.create_assessment(name=name, target_id=target_id)
    if target_name:
        asmt["target_name"] = target_name
        STORE._persist(asmt["id"])
    return asmt


@router.get("/assessments", summary="List all assessments")
def list_assessments() -> List[Dict[str, Any]]:
    """List summary information for all assessments."""
    asmts = STORE.list_assessments()
    summaries = []
    for a in asmts:
        summaries.append({
            "id": a["id"],
            "name": a["name"],
            "target_id": a.get("target_id"),
            "target_name": a.get("target_name"),
            "status": a.get("status"),
            "created_at": a.get("created_at"),
            "updated_at": a.get("updated_at"),
            "runs_count": len(a.get("runs", [])),
            "findings_count": len(a.get("findings", [])),
        })
    # Sort newest first
    summaries.sort(key=lambda s: s["created_at"], reverse=True)
    return summaries


@router.get("/assessments/{assessment_id}", summary="Get assessment details")
def get_assessment(assessment_id: str = PathParam(..., description="Assessment identifier")) -> Dict[str, Any]:
    """Retrieve full assessment record by ID."""
    asmt = STORE.get_assessment(assessment_id)
    if not asmt:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")
    return asmt


@router.post(
    "/assessments/{assessment_id}/target",
    response_model=TargetSelectionResponse,
    summary="Select target for an assessment",
)
def select_assessment_target(
    assessment_id: str = PathParam(..., description="Assessment identifier"),
    request: TargetSelectionRequest = ...,
) -> TargetSelectionResponse:
    """Select a target configuration for an assessment run."""
    asmt = STORE.get_assessment(assessment_id)
    if not asmt:
        # Create it automatically if needed so integration flows don't stumble
        asmt = STORE.create_assessment(name=f"Assessment {assessment_id}")
        asmt["id"] = assessment_id
        STORE.assessments[assessment_id] = asmt

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

    STORE.update_target(assessment_id, target["id"], target["name"])

    return TargetSelectionResponse(
        assessment_id=assessment_id,
        target_id=target["id"],
        target_name=target["name"],
        status="target_selected",
        message="Target selected successfully. Ready for attack execution.",
    )


# ---------------------------------------------------------------------------
# 3. Runs & Traces
# ---------------------------------------------------------------------------

@router.post("/assessments/{assessment_id}/runs", summary="Start assessment runs")
def start_assessment_runs(
    assessment_id: str = PathParam(..., description="Assessment identifier"),
    mode: Optional[str] = Query("deterministic_simulation", description="Execution mode: 'deterministic_simulation' or 'real_sandbox'"),
) -> Dict[str, Any]:
    """Execute the seed attack benchmark suite against the configured target."""
    asmt = STORE.get_assessment(assessment_id)
    if not asmt:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")

    if not asmt.get("target_id"):
        raise HTTPException(
            status_code=400,
            detail="No target selected. Call POST /assessments/{id}/target before executing runs.",
        )

    executed_runs = execute_seed_runs(assessment_id, execution_mode=mode or "deterministic_simulation")
    return {
        "assessment_id": assessment_id,
        "status": "completed",
        "runs_executed": len(executed_runs),
        "runs": executed_runs,
    }


@router.get("/assessments/{assessment_id}/runs", summary="List runs for an assessment")
def list_assessment_runs(
    assessment_id: str = PathParam(..., description="Assessment identifier")
) -> List[Dict[str, Any]]:
    """Retrieve all execution runs associated with an assessment."""
    asmt = STORE.get_assessment(assessment_id)
    if not asmt:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")
    return asmt.get("runs", [])


@router.get("/assessments/{assessment_id}/runs/{run_id}", summary="Get run details and trace")
def get_assessment_run_detail(
    assessment_id: str = PathParam(..., description="Assessment identifier"),
    run_id: str = PathParam(..., description="Run identifier"),
) -> Dict[str, Any]:
    """Retrieve detailed run metadata and raw trace steps."""
    asmt = STORE.get_assessment(assessment_id)
    if not asmt:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")

    matching_run = next((r for r in asmt.get("runs", []) if r.get("run_id") == run_id), None)
    if not matching_run:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found in assessment '{assessment_id}'.")
    return matching_run


@router.get("/runs/{run_id}", summary="Get run by run ID across all assessments")
def get_run_by_id(run_id: str = PathParam(..., description="Run identifier")) -> Dict[str, Any]:
    """Global lookup for a run across all stored assessments."""
    for asmt in STORE.list_assessments():
        for r in asmt.get("runs", []):
            if r.get("run_id") == run_id:
                return r
    raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")


# ---------------------------------------------------------------------------
# 4. Findings
# ---------------------------------------------------------------------------

@router.get("/assessments/{assessment_id}/findings", summary="List findings for an assessment")
def list_assessment_findings(
    assessment_id: str = PathParam(..., description="Assessment identifier"),
    source: Optional[str] = Query(None, description="Optional filter by source (seed, generated, recorded)"),
) -> List[Dict[str, Any]]:
    """Retrieve security findings for an assessment, preserving finding source."""
    asmt = STORE.get_assessment(assessment_id)
    if not asmt:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")

    findings = asmt.get("findings", [])
    if source:
        findings = [f for f in findings if f.get("source") == source]
    return findings


@router.get("/findings", summary="List all findings across assessments")
def list_all_findings() -> List[Dict[str, Any]]:
    """Global lookup of all findings recorded across assessments."""
    all_f = []
    for a in STORE.list_assessments():
        all_f.extend(a.get("findings", []))
    return all_f


# ---------------------------------------------------------------------------
# 5. Defenses Management
# ---------------------------------------------------------------------------

@router.get("/defenses", summary="List global default defenses")
def list_global_defenses() -> List[Dict[str, Any]]:
    """List available defense configurations and their default status."""
    return DEFAULT_DEFENSES


@router.get("/assessments/{assessment_id}/defenses", summary="List defenses for assessment")
def list_assessment_defenses(
    assessment_id: str = PathParam(..., description="Assessment identifier")
) -> List[Dict[str, Any]]:
    """List active defense controls and status for a specific assessment."""
    asmt = STORE.get_assessment(assessment_id)
    if not asmt:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")
    return asmt.get("defenses", [])


@router.post("/defenses/{defense_id}/toggle", summary="Toggle defense status globally")
def toggle_global_defense(defense_id: str = PathParam(..., description="Defense identifier")) -> Dict[str, Any]:
    """Toggle defense status in the default defense set."""
    for d in DEFAULT_DEFENSES:
        if d["id"] == defense_id:
            d["status"] = "disabled" if d["status"] == "enforced" else "enforced"
            return d
    raise HTTPException(status_code=404, detail=f"Defense '{defense_id}' not found.")


@router.post("/assessments/{assessment_id}/defenses/{defense_id}/toggle", summary="Toggle defense for assessment")
def toggle_assessment_defense(
    assessment_id: str = PathParam(..., description="Assessment identifier"),
    defense_id: str = PathParam(..., description="Defense identifier"),
) -> Dict[str, Any]:
    """Toggle a defense on/off for a specific assessment."""
    try:
        updated = STORE.toggle_defense(assessment_id, defense_id)
        return updated
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/assessments/{assessment_id}/defenses/evolve", summary="Evolve defenses based on exploit findings")
def evolve_defenses(
    assessment_id: str = PathParam(..., description="Assessment identifier")
) -> Dict[str, Any]:
    """Execute dynamic defense evolution loop: generates candidates, evaluates in isolation, promotes if accepted."""
    try:
        result = execute_evolution_cycle(assessment_id)
        return result
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Evolution error: {exc}")


@router.get("/assessments/{assessment_id}/defenses/candidates", summary="List proposed defense candidates")
def list_defense_candidates(
    assessment_id: str = PathParam(..., description="Assessment identifier")
) -> List[Dict[str, Any]]:
    """Retrieve all proposed defense candidates and evaluation scorecards for target."""
    try:
        candidates = get_defense_candidates_for_assessment(assessment_id)
        return candidates
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/assessments/{assessment_id}/defenses/candidates/{candidate_id}/apply", summary="Apply candidate defense")
def apply_defense_candidate(
    assessment_id: str = PathParam(..., description="Assessment identifier"),
    candidate_id: str = PathParam(..., description="Candidate identifier"),
) -> Dict[str, Any]:
    """Promote an evaluated candidate defense to the active policy version."""
    try:
        promoted = apply_defense_candidate_for_assessment(assessment_id, candidate_id)
        return promoted
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/assessments/{assessment_id}/defenses/rollback", summary="Rollback defense policy version")
def rollback_defense(
    assessment_id: str = PathParam(..., description="Assessment identifier")
) -> Dict[str, Any]:
    """Roll back active defense policy to parent or previous version."""
    try:
        restored = rollback_defense_for_assessment(assessment_id)
        return restored
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/assessments/{assessment_id}/defenses/history", summary="Get defense policy version history")
def get_defense_history(
    assessment_id: str = PathParam(..., description="Assessment identifier")
) -> Dict[str, Any]:
    """Retrieve complete policy version history and active snapshot for assessment target."""
    try:
        history_info = get_defense_history_for_assessment(assessment_id)
        return history_info
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# 6. Adaptive Challenge & Retest
# ---------------------------------------------------------------------------

@router.post("/assessments/{assessment_id}/challenge", summary="Challenge configured defenses")
def challenge_defenses(
    assessment_id: str = PathParam(..., description="Assessment identifier"),
    mode: Optional[str] = Query("deterministic_simulation", description="Execution mode: 'deterministic_simulation' or 'real_sandbox'"),
    use_model: bool = Query(False, description="Whether to use model-backed attack generation"),
) -> Dict[str, Any]:
    """Adaptive attacker feedback challenge: mutates blocked attacks and challenges active defenses."""
    asmt = STORE.get_assessment(assessment_id)
    if not asmt:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")

    if not asmt.get("runs"):
        raise HTTPException(
            status_code=400,
            detail="No initial runs found to challenge. Run initial tests before challenging defenses.",
        )

    try:
        result = execute_adaptive_challenge(
            assessment_id,
            execution_mode=mode or "deterministic_simulation",
            use_model=use_model,
        )
        return result
    except RuntimeError as rexc:
        raise HTTPException(status_code=409, detail=str(rexc))


@router.post("/assessments/{assessment_id}/challenge/reset", summary="Reset adaptive challenge attempt history")
def reset_adaptive_challenge(
    assessment_id: str = PathParam(..., description="Assessment identifier"),
) -> Dict[str, Any]:
    """Reset adaptive challenge runs and allow retesting strategy pool from attempt 1."""
    asmt = STORE.get_assessment(assessment_id)
    if not asmt:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")
    return STORE.reset_challenge_runs(assessment_id)


@router.post("/assessments/{assessment_id}/adaptive-loop", summary="Run multi-round adaptive red-team and defense loop")
def run_adaptive_loop(
    assessment_id: str = PathParam(..., description="Assessment identifier"),
    max_rounds: int = Query(5, description="Maximum number of red-team rounds"),
    mode: Optional[str] = Query("deterministic_offline", description="Target execution mode: 'deterministic_offline' or 'model_backed'"),
    use_model: bool = Query(False, description="Whether attacker uses real model generation"),
) -> Dict[str, Any]:
    """Execute complete multi-round adaptive red-team and defense evolution loop."""
    asmt = STORE.get_assessment(assessment_id)
    if not asmt:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")

    result = execute_adaptive_red_team_loop(
        asmt_id=assessment_id,
        max_rounds=max_rounds,
        target_execution_mode=mode or "deterministic_offline",
        attacker_use_model=use_model,
    )
    return result


@router.post("/assessments/{assessment_id}/retest", summary="Retest assessment defenses")
def retest_assessment(
    assessment_id: str = PathParam(..., description="Assessment identifier"),
    mode: Optional[str] = Query("deterministic_simulation", description="Execution mode: 'deterministic_simulation' or 'real_sandbox'"),
) -> Dict[str, Any]:
    """Run before-and-after retest evaluation comparing exploit rates and legitimate task pass rates."""
    asmt = STORE.get_assessment(assessment_id)
    if not asmt:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")

    retest_result = execute_retest(
        assessment_id,
        execution_mode=mode or "deterministic_simulation",
    )
    return retest_result


# ---------------------------------------------------------------------------
# 7. Final Report
# ---------------------------------------------------------------------------

@router.get("/assessments/{assessment_id}/report", summary="Retrieve final assessment report")
def get_assessment_report(
    assessment_id: str = PathParam(..., description="Assessment identifier")
) -> Dict[str, Any]:
    """Generate and return the full security assessment report from saved run data."""
    asmt = STORE.get_assessment(assessment_id)
    if not asmt:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")

    report = build_assessment_report(assessment_id)
    return report


# ---------------------------------------------------------------------------
# 8. Evidence Hash Chain & Tamper Verification
# ---------------------------------------------------------------------------

@router.post("/assessments/{assessment_id}/verify-chain", summary="Verify evidence hash chain")
def verify_chain(
    assessment_id: str = PathParam(..., description="Assessment identifier")
) -> Dict[str, Any]:
    """Verify cryptographic integrity of all logged execution evidence."""
    asmt = STORE.get_assessment(assessment_id)
    if not asmt:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")

    verification = verify_evidence_chain(assessment_id)
    return verification


@router.post("/assessments/{assessment_id}/tamper-test", summary="Run isolated tamper demonstration")
def tamper_test(
    assessment_id: str = PathParam(..., description="Assessment identifier")
) -> Dict[str, Any]:
    """Test cryptographic tamper detection on a disposable copy of the evidence chain."""
    asmt = STORE.get_assessment(assessment_id)
    if not asmt:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")

    result = run_tamper_demonstration(assessment_id)
    return result


# ---------------------------------------------------------------------------
# 9. Recorded Fixture Endpoint (Offline/Backup Inspection)
# ---------------------------------------------------------------------------

@router.get("/recorded/runs", summary="Get recorded baseline run fixture")
def get_recorded_fixture() -> Dict[str, Any]:
    """Return the sanitized recorded demo fixture for offline presentation inspection."""
    if not RECORDED_DATA_PATH.exists():
        raise HTTPException(status_code=404, detail="Recorded fixture not found.")
    try:
        with open(RECORDED_DATA_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read recorded fixture: {exc}")


# ---------------------------------------------------------------------------
# 10. Browser Extension Sentinel Endpoints (Companion Integration)
# ---------------------------------------------------------------------------

class ExtensionScanRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=16000, description="User-approved text snippet to inspect")
    context_url: Optional[str] = Field(None, max_length=500, description="URL or origin where text was captured")
    target_id: Optional[str] = Field("demo-company-assistant", description="Target configuration for canary extraction")
    assessment_id: Optional[str] = Field(None, description="Optional active assessment ID to link findings")
    consent_given: bool = Field(True, description="Explicit user consent confirmation")


@router.get("/extension/health", summary="AgentBreak Sentinel extension integration health check")
def extension_health() -> Dict[str, Any]:
    """Check availability of Sentinel extension backend companion."""
    from analyzer.heuristic_scanner import SCANNER_RULES
    return {
        "status": "healthy",
        "companion": "AgentBreak Sentinel",
        "version": "1.0.0",
        "rules_count": len(SCANNER_RULES),
        "supported_targets": ["demo-company-assistant"],
        "privacy": {
            "telemetry_collected": False,
            "user_initiated_only": True,
            "plain_text_storage": False,
            "retention": "ephemeral_in_memory",
        },
    }


@router.get("/extension/download", summary="Download AgentBreak Sentinel Chrome Extension ZIP package")
@router.get("/AgentBreak-Sentinel-Chrome-Extension.zip", summary="Direct download endpoint for Sentinel Chrome Extension ZIP")
def download_sentinel_extension():
    """Returns the compiled, loadable Sentinel Chrome Extension ZIP package."""
    from fastapi.responses import FileResponse
    repo_root = Path(__file__).resolve().parent.parent
    candidates = [
        repo_root / "dashboard" / "public" / "AgentBreak-Sentinel-Chrome-Extension.zip",
        repo_root / "dashboard" / "dist" / "AgentBreak-Sentinel-Chrome-Extension.zip",
        repo_root / "extension" / "dist" / "AgentBreak-Sentinel-Chrome-Extension.zip",
    ]
    zip_path = None
    for c in candidates:
        if c.is_file():
            zip_path = c
            break

    if not zip_path:
        try:
            sys_path = str(repo_root)
            if sys_path not in os.sys.path:
                os.sys.path.insert(0, sys_path)
            from extension.scripts.package_extension import package_sentinel_extension
            zip_path = package_sentinel_extension()
        except Exception as exc:
            raise HTTPException(
                status_code=404,
                detail=f"Sentinel extension ZIP is not built yet: {exc}",
            )

    return FileResponse(
        str(zip_path),
        media_type="application/zip",
        filename="AgentBreak-Sentinel-Chrome-Extension.zip",
    )


@router.post("/extension/scan", summary="Analyze user-approved text excerpt with Sentinel rules")
def extension_scan(req: ExtensionScanRequest) -> Dict[str, Any]:
    """Scan user-approved text snippet using explainable heuristic rules and canary detection."""
    import uuid
    from datetime import datetime, timezone
    from analyzer.heuristic_scanner import scan_text_heuristics

    if not req.consent_given:
        raise HTTPException(
            status_code=400,
            detail="Explicit user consent is required before analyzing text with AgentBreak Sentinel.",
        )

    # Resolve target configuration for canary lookup
    target_cfg = None
    target_id = req.target_id or "demo-company-assistant"
    configs_dir = get_configs_dir()
    candidate_path = configs_dir / f"{target_id}.yaml"
    if candidate_path.exists():
        try:
            with open(candidate_path, "r", encoding="utf-8") as f:
                target_cfg = yaml.safe_load(f)
        except Exception:
            pass

    # Run deterministic heuristic scanner
    scan_result = scan_text_heuristics(req.content, target_config=target_cfg)

    scan_id = f"ext-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    excerpt = req.content[:160] + ("..." if len(req.content) > 160 else "")

    mitigations = []
    for r in scan_result["rules_matched"]:
        if r.get("mitigation") and r["mitigation"] not in mitigations:
            mitigations.append(r["mitigation"])
    if not mitigations:
        mitigations.append("No immediate mitigation required for benign content. Continue monitoring.")

    # If an active assessment was provided and exists, record the scan in assessment metadata
    linked_asmt_id = None
    if req.assessment_id:
        asmt = STORE.get_assessment(req.assessment_id)
        if asmt:
            linked_asmt_id = req.assessment_id
            ext_scans = asmt.setdefault("extension_scans", [])
            ext_scans.append({
                "scan_id": scan_id,
                "timestamp": now,
                "risk_level": scan_result["risk_level"],
                "rules_matched_count": len(scan_result["rules_matched"]),
                "context_url": req.context_url,
            })
            STORE._persist(req.assessment_id)

    return {
        "scan_id": scan_id,
        "timestamp": now,
        "status": "completed",
        "risk_level": scan_result["risk_level"],
        "content_length": len(req.content),
        "sanitized_excerpt": excerpt,
        "rules_matched": scan_result["rules_matched"],
        "summary": scan_result["summary"],
        "is_heuristic_only": True,
        "is_trace_verified": False,
        "linked_assessment_id": linked_asmt_id,
        "mitigation_advice": mitigations,
        "privacy_notice": (
            "Analyzed in ephemeral memory. No cookies, passwords, or session tokens were captured. "
            "This heuristic scan evaluates text patterns; it is not an agent execution exploit proof."
        ),
    }

