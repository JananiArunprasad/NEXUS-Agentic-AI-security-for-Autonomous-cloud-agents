import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.security.session_state import (
    get_session,
)


# =========================================================
# PATH CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parents[2]

LOG_DIRECTORY = BASE_DIR / "logs"

AUDIT_LOG_FILE = (
    LOG_DIRECTORY
    / "nexus_audit.jsonl"
)


# =========================================================
# AUDIT LOGGER
# =========================================================

def log_security_event(
    session_id: str,
    request: dict,
    enforcement_result: dict,
):
    """
    Store one NEXUS security decision.

    Important:
    We deliberately avoid storing tool arguments or
    secret values in the audit log.
    """

    LOG_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    session = get_session(
        session_id
    )

    # -----------------------------------------------------
    # Safe session information
    # -----------------------------------------------------

    agent_id = None
    task_id = None

    if session is not None:

        agent_id = session.get(
            "agent_id"
        )

        task_id = session.get(
            "task_id"
        )

    # -----------------------------------------------------
    # Risk information
    # -----------------------------------------------------

    risk = enforcement_result.get(
        "risk",
        {},
    )

    risk_score = risk.get(
        "score"
    )

    risk_level = risk.get(
        "risk_level"
    )

    # -----------------------------------------------------
    # Containment information
    # -----------------------------------------------------

    containment = (
        enforcement_result.get(
            "containment_after"
        )
        or enforcement_result.get(
            "containment_before"
        )
        or {}
    )

    containment_mode = (
        containment.get(
            "containment_mode"
        )
    )

    restricted = containment.get(
        "restrict"
    )

    blocked_capability = (
        enforcement_result.get(
            "blocked_capability"
        )
    )

    if (
        blocked_capability is None
        and isinstance(restricted, dict)
    ):

        blocked_capability = (
            restricted.get(
                "capability"
            )
        )

    # -----------------------------------------------------
    # Build safe audit event
    # -----------------------------------------------------

    audit_event = {

        "event_id":
            f"audit-{uuid4().hex[:10]}",

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "session_id":
            session_id,

        "agent_id":
            agent_id,

        "task_id":
            task_id,

        "event": (
            f"{request.get('service')}:"
            f"{request.get('action')}"
        ),

        "service":
            request.get(
                "service"
            ),

        "action":
            request.get(
                "action"
            ),

        "capability":
            request.get(
                "capability"
            ),

        "resource":
            request.get(
                "resource"
            ),

        "decision":
            enforcement_result.get(
                "decision"
            ),

        "executed":
            enforcement_result.get(
                "executed",
                False,
            ),

        "reason":
            enforcement_result.get(
                "reason"
            ),

        "risk_score":
            risk_score,

        "risk_level":
            risk_level,

        "containment_mode":
            containment_mode,

        "blocked_capability":
            blocked_capability,
    }

    # -----------------------------------------------------
    # Append event to JSONL log
    # -----------------------------------------------------

    with AUDIT_LOG_FILE.open(
        "a",
        encoding="utf-8",
    ) as file:

        file.write(
            json.dumps(
                audit_event
            )
            + "\n"
        )

    return audit_event


# =========================================================
# READ AUDIT EVENTS
# =========================================================

def read_audit_events(
    limit: int = 50,
):
    """
    Return the newest audit events.

    Used later by the API and dashboard.
    """

    if not AUDIT_LOG_FILE.exists():
        return []

    events = []

    with AUDIT_LOG_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:

                events.append(
                    json.loads(line)
                )

            except json.JSONDecodeError:

                continue

    return events[-limit:]


# =========================================================
# CLEAR AUDIT LOG
# =========================================================

def clear_audit_log():
    """
    Clear the local audit log.

    Mainly used by automated tests.
    """

    if AUDIT_LOG_FILE.exists():

        AUDIT_LOG_FILE.unlink()