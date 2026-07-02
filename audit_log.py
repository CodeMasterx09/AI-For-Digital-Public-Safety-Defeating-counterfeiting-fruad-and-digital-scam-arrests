"""
Tamper-evident audit log — chain-of-custody for PRAHARI AI case files.

Each entry's SHA-256 hash is computed over its own content PLUS the previous
entry's hash. This means altering any past entry invalidates every hash that
follows it, making tampering detectable without a blockchain.

Verify integrity at any time via the /audit/verify endpoint.
"""
import hashlib
import json
from datetime import datetime, timezone

_log: list[dict] = []


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def append_event(event_type: str, metadata: dict = None) -> dict:
    """Append a tamper-evident event to the audit log. Returns the new entry."""
    if metadata is None:
        metadata = {}
    seq = len(_log) + 1
    timestamp = _now_iso()
    prev_hash = _log[-1]["hash"] if _log else "0" * 64
    payload = (
        f"{seq}|{timestamp}|{event_type}"
        f"|{json.dumps(metadata, sort_keys=True)}"
        f"|{prev_hash}"
    )
    entry = {
        "seq": seq,
        "timestamp": timestamp,
        "event_type": event_type,
        "metadata": metadata,
        "hash": hashlib.sha256(payload.encode()).hexdigest(),
    }
    _log.append(entry)
    return entry


def get_log() -> list[dict]:
    """Return a copy of the full audit log."""
    return list(_log)


def verify_chain() -> tuple[bool, str]:
    """Walk the entire chain and verify every hash. Returns (ok, message)."""
    prev_hash = "0" * 64
    for entry in _log:
        payload = (
            f"{entry['seq']}|{entry['timestamp']}|{entry['event_type']}"
            f"|{json.dumps(entry['metadata'], sort_keys=True)}"
            f"|{prev_hash}"
        )
        expected = hashlib.sha256(payload.encode()).hexdigest()
        if expected != entry["hash"]:
            return False, f"Chain broken at seq={entry['seq']} — hash mismatch."
        prev_hash = entry["hash"]
    return True, f"Chain intact across {len(_log)} entries."


if __name__ == "__main__":
    append_event("SYSTEM_START", {"service": "PRAHARI AI"})
    append_event("ALERT_GENERATED", {"session_id": "abc123", "risk": 78})
    append_event("CASE_FILE_EXPORTED", {"cluster_id": 1})
    ok, msg = verify_chain()
    print(f"verify: {ok} — {msg}")
    for e in get_log():
        print(f"  [{e['seq']}] {e['event_type']} | hash={e['hash'][:16]}...")
