"""Cryptographic Hash-Chained Trace Logger and Storage for AgentBreak (P1).

Manages trace records and guarantees tamper-evident logging:
- Computes sha256(prev_hash + canonical_json(record without hash)).
- Genesis record starts with standard 64-char zero hash '0' * 64.
- Thread-safe persistence to data/traces/{run_id}.json.
- Chain verification function for auditability (POST /verify-chain).
"""

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
TRACES_DIR = DATA_DIR / "traces"
CHAIN_INDEX_FILE = DATA_DIR / "trace_chain.json"

GENESIS_PREV_HASH = "0" * 64

_TRACE_LOCK = threading.Lock()


def canonical_json(data: Dict[str, Any]) -> str:
    """Produce deterministic canonical JSON representation for hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_trace_hash(prev_hash: str, record_without_hash: Dict[str, Any]) -> str:
    """Compute sha256(prev_hash + canonical_json(record_without_hash))."""
    canonical_repr = canonical_json(record_without_hash)
    payload = prev_hash + canonical_repr
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class TraceLogger:
    """Thread-safe hash-chained trace logger."""

    def __init__(self, traces_dir: Optional[Path] = None, chain_index: Optional[Path] = None):
        self.traces_dir = traces_dir or TRACES_DIR
        self.chain_index = chain_index or CHAIN_INDEX_FILE
        self.traces_dir.mkdir(parents=True, exist_ok=True)
        self.chain_index.parent.mkdir(parents=True, exist_ok=True)

    def _get_last_state(self) -> Tuple[str, int]:
        """Read the most recent hash and sequence number from chain index or traces."""
        if self.chain_index.exists():
            try:
                with open(self.chain_index, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data.get("last_hash", GENESIS_PREV_HASH), data.get("last_seq", 0)
            except Exception:
                pass

        # If index missing, check existing trace files
        existing_files = list(self.traces_dir.glob("*.json"))
        if existing_files:
            traces_loaded = []
            for p in existing_files:
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        traces_loaded.append(json.load(f))
                except Exception:
                    pass
            if traces_loaded:
                traces_loaded.sort(key=lambda t: t.get("seq", 0))
                last_trace = traces_loaded[-1]
                return last_trace.get("hash", GENESIS_PREV_HASH), last_trace.get("seq", len(traces_loaded))

        return GENESIS_PREV_HASH, 0

    def _update_last_state(self, run_id: str, new_hash: str, new_seq: int) -> None:
        """Update the chain index file."""
        data = {
            "last_run_id": run_id,
            "last_hash": new_hash,
            "last_seq": new_seq,
        }
        with open(self.chain_index, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def log_trace(self, trace_data: Dict[str, Any]) -> Dict[str, Any]:
        """Finalize, hash, and persist a trace record.

        Thread-safe: guarantees monotonic chain progression even under concurrency.
        """
        with _TRACE_LOCK:
            run_id = trace_data.get("run_id", "run_unknown")
            prev_hash, last_seq = self._get_last_state()
            new_seq = last_seq + 1

            # Prepare record for hashing (exclude any existing 'hash' key)
            record_to_hash = {k: v for k, v in trace_data.items() if k != "hash"}
            record_to_hash["seq"] = new_seq
            record_to_hash["prev_hash"] = prev_hash

            # Calculate cryptographic hash
            calculated_hash = compute_trace_hash(prev_hash, record_to_hash)
            record_to_hash["hash"] = calculated_hash

            # Save trace file
            trace_path = self.traces_dir / f"{run_id}.json"
            with open(trace_path, "w", encoding="utf-8") as f:
                json.dump(record_to_hash, f, indent=2, ensure_ascii=False)

            # Update chain state
            self._update_last_state(run_id, calculated_hash, new_seq)

            return record_to_hash


def verify_trace_chain(traces_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Verify cryptographic integrity of all saved traces in the chain.

    Checks:
    1. Traces ordered monotonically by sequence number.
    2. Each trace's computed hash matches trace['hash'].
    3. Each trace's prev_hash matches the previous trace's hash (genesis matches GENESIS_PREV_HASH).
    """
    directory = traces_dir or TRACES_DIR
    if not directory.exists():
        return {
            "valid": True,
            "total_traces": 0,
            "broken_at": None,
            "details": "Trace directory is empty; no traces to verify.",
        }

    raw_files = list(directory.glob("*.json"))
    if not raw_files:
        return {
            "valid": True,
            "total_traces": 0,
            "broken_at": None,
            "details": "Zero traces recorded.",
        }

    records_with_path = []
    for file_path in raw_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                record = json.load(f)
                records_with_path.append((record, file_path))
        except Exception as exc:
            return {
                "valid": False,
                "total_traces": len(raw_files),
                "broken_at": file_path.name,
                "details": f"Failed to parse trace file '{file_path.name}': {exc}",
            }

    # Sort strictly by sequence number
    records_with_path.sort(key=lambda item: item[0].get("seq", 0))

    expected_prev_hash = GENESIS_PREV_HASH
    for idx, (record, file_path) in enumerate(records_with_path):
        rec_prev = record.get("prev_hash")
        rec_hash = record.get("hash")
        run_id = record.get("run_id", file_path.stem)

        # 1. Check prev_hash linkage
        if rec_prev != expected_prev_hash:
            return {
                "valid": False,
                "total_traces": len(records_with_path),
                "broken_at": run_id,
                "details": (
                    f"Chain break at run '{run_id}': record prev_hash '{rec_prev}' does not match "
                    f"expected hash '{expected_prev_hash}'."
                ),
            }

        # 2. Check hash recalculation
        record_without_hash = {k: v for k, v in record.items() if k != "hash"}
        recomputed_hash = compute_trace_hash(rec_prev, record_without_hash)

        if recomputed_hash != rec_hash:
            return {
                "valid": False,
                "total_traces": len(records_with_path),
                "broken_at": run_id,
                "details": (
                    f"Tamper detected at run '{run_id}': stored hash '{rec_hash}' does not match "
                    f"recomputed hash '{recomputed_hash}'."
                ),
            }

        expected_prev_hash = rec_hash

    return {
        "valid": True,
        "total_traces": len(records_with_path),
        "broken_at": None,
        "details": f"All {len(records_with_path)} traces successfully verified. Hash chain unmodified since logging.",
    }
