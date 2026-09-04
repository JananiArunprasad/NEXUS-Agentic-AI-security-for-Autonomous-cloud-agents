from app.security.session_state import (
    create_session,
    get_session,
    record_action,
    clear_sessions,
)


def setup_function():

    clear_sessions()


def test_create_session():

    session = create_session(
        agent_id="CloudOps-Agent-01",
        task_id="task-ec2-troubleshoot",
        task_description="Diagnose EC2 high CPU",
    )

    assert session["agent_id"] == (
        "CloudOps-Agent-01"
    )

    assert session["status"] == "ACTIVE"

    assert session["actions"] == []


def test_record_first_action():

    session = create_session(
        agent_id="CloudOps-Agent-01",
        task_id="task-ec2-troubleshoot",
        task_description="Diagnose EC2 high CPU",
    )

    action = {
        "service": "EC2",
        "action": "DescribeInstances",
        "resource": "i-demo123",
        "timestamp": "demo-time",
    }

    result = record_action(
        session["session_id"],
        action,
    )

    assert result["sequence"] == 1

    assert result["event"] == (
        "EC2:DescribeInstances"
    )


def test_actions_preserve_order():

    session = create_session(
        agent_id="CloudOps-Agent-01",
        task_id="task-ec2-troubleshoot",
        task_description="Diagnose EC2 high CPU",
    )

    first_action = {
        "service": "EC2",
        "action": "DescribeInstances",
        "resource": "i-demo123",
    }

    second_action = {
        "service": "CloudWatch",
        "action": "GetMetricData",
        "resource": "i-demo123",
    }

    record_action(
        session["session_id"],
        first_action,
    )

    record_action(
        session["session_id"],
        second_action,
    )

    stored_session = get_session(
        session["session_id"]
    )

    assert (
        stored_session["actions"][0]["sequence"]
        == 1
    )

    assert (
        stored_session["actions"][1]["sequence"]
        == 2
    )

    assert (
        stored_session["actions"][0]["event"]
        == "EC2:DescribeInstances"
    )

    assert (
        stored_session["actions"][1]["event"]
        == "CloudWatch:GetMetricData"
    )