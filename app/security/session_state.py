from datetime import datetime, timezone
from uuid import uuid4


# ---------------------------------------------------------
# In-memory session store
# ---------------------------------------------------------

SESSIONS = {}


def create_session(
    agent_id: str,
    task_id: str,
    task_description: str,
):
    """
    Create a new runtime session for an authorized agent.
    """

    session_id = f"session-{uuid4().hex[:8]}"

    session = {
        "session_id": session_id,
        "agent_id": agent_id,
        "task_id": task_id,
        "task_description": task_description,
        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "status": "ACTIVE",
        "actions": [],
    }

    SESSIONS[session_id] = session

    return session


def get_session(session_id: str):
    """
    Retrieve an existing runtime session.
    """

    return SESSIONS.get(session_id)


def record_action(
    session_id: str,
    action: dict,
):
    """
    Add one observed cloud action to the session history.
    """

    session = get_session(session_id)

    if session is None:
        return None

    sequence_number = (
        len(session["actions"]) + 1
    )

    action_record = {
        "sequence": sequence_number,

        "event": (
            f"{action['service']}:"
            f"{action['action']}"
        ),

        "service": action["service"],

        "action": action["action"],

        "resource": action["resource"],

        "tool_timestamp": action.get(
            "timestamp"
        ),

        "observed_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    session["actions"].append(
        action_record
    )

    return action_record


def clear_sessions():
    """
    Clear all stored sessions.

    Used mainly by automated tests.
    """

    SESSIONS.clear()
def set_session_status(
    session_id: str,
    status: str,
):
    """
    Change the runtime status of an existing session.
    """

    session = get_session(
        session_id
    )

    if session is None:
        return False

    session["status"] = status

    return True