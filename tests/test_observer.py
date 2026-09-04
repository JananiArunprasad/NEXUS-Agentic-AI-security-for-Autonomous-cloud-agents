from app.security.observer import (
    observe_action,
)

from app.security.session_state import (
    create_session,
    get_session,
    clear_sessions,
)


def setup_function():

    clear_sessions()


def test_observer_records_action():

    session = create_session(
        agent_id="CloudOps-Agent-01",
        task_id="task-ec2-troubleshoot",
        task_description="Diagnose EC2 high CPU",
    )

    action = {
        "service": "IAM",
        "action": "ListRoles",
        "resource": "aws-account",
    }

    result = observe_action(
        session["session_id"],
        action,
    )

    assert result["success"] is True

    stored_session = get_session(
        session["session_id"]
    )

    assert len(
        stored_session["actions"]
    ) == 1

    assert (
        stored_session["actions"][0]["event"]
        == "IAM:ListRoles"
    )


def test_unknown_session_is_rejected():

    result = observe_action(
        "session-does-not-exist",
        {
            "service": "EC2",
            "action": "DescribeInstances",
            "resource": "i-demo123",
        },
    )

    assert result["success"] is False