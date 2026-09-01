from app.security.identity_gate import verify_agent


def test_valid_agent():

    result = verify_agent(
        agent_id="CloudOps-Agent-01",
        credential="nexus-demo-key-01",
        task_id="task-ec2-troubleshoot",
    )

    assert result["authorized"] is True
    assert result["decision"] == "ALLOW"


def test_unknown_agent():

    result = verify_agent(
        agent_id="Unknown-Agent",
        credential="anything",
        task_id="task-ec2-troubleshoot",
    )

    assert result["authorized"] is False
    assert result["decision"] == "QUARANTINE"


def test_invalid_credential():

    result = verify_agent(
        agent_id="CloudOps-Agent-01",
        credential="wrong-password",
        task_id="task-ec2-troubleshoot",
    )

    assert result["authorized"] is False
    assert result["decision"] == "QUARANTINE"


def test_unauthorized_task():

    result = verify_agent(
        agent_id="CloudOps-Agent-01",
        credential="nexus-demo-key-01",
        task_id="task-access-payroll",
    )

    assert result["authorized"] is False
    assert result["decision"] == "BLOCK"