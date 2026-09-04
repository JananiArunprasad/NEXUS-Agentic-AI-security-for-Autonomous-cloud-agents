from app.security.session_state import (
    get_session,
    record_action,
)


def observe_action(
    session_id: str,
    action: dict,
):
    """
    Observe and record a single runtime cloud action.

    The Observer does NOT decide whether the action
    is malicious.

    Its responsibility is to normalize and record
    agent activity for later security analysis.
    """

    session = get_session(
        session_id
    )

    if session is None:

        return {
            "success": False,
            "error": "Unknown runtime session.",
        }

    if session["status"] != "ACTIVE":

        return {
            "success": False,
            "error": "Session is not active.",
        }

    action_record = record_action(
        session_id,
        action,
    )

    return {
        "success": True,
        "observer": "runtime_observer",
        "session_id": session_id,
        "recorded_action": action_record,
    }