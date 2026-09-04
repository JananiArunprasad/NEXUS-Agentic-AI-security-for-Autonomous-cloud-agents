from app.audit.logger import (
    clear_audit_log,
    read_audit_events,
)

from app.security.enforcer import (
    enforce_action,
)

from app.security.session_state import (
    create_session,
    clear_sessions,
)


ALLOWED_SERVICES = [
    "EC2",
    "CloudWatch",
]

ALLOWED_RESOURCES = [
    "i-demo123",
]


def setup_function():

    clear_sessions()
    clear_audit_log()


def make_session():

    return create_session(
        agent_id="CloudOps-Agent-01",
        task_id="task-ec2-troubleshoot",
        task_description="Diagnose EC2 high CPU",
    )


def test_allowed_action_is_logged():

    session = make_session()

    request = {
        "tool_name": "check_ec2",
        "service": "EC2",
        "action": "DescribeInstances",
        "capability": "ec2:DescribeInstances",
        "resource": "i-demo123",
        "arguments": {
            "instance_id": "i-demo123"
        },
    }

    result = enforce_action(
        session_id=session["session_id"],

        request=request,

        allowed_services=
            ALLOWED_SERVICES,

        allowed_resources=
            ALLOWED_RESOURCES,

        identity_trusted=True,

        task_trusted=True,
    )

    assert result["decision"] == "ALLOW"

    events = read_audit_events()

    assert len(events) == 1

    assert (
        events[0]["event"]
        ==
        "EC2:DescribeInstances"
    )

    assert (
        events[0]["decision"]
        ==
        "ALLOW"
    )


def test_blocked_action_is_logged():

    session = make_session()

    iam_request = {
        "tool_name": "list_iam_roles",
        "service": "IAM",
        "action": "ListRoles",
        "capability": "iam:ListRoles",
        "resource": "aws-account",
        "arguments": {},
    }

    secret_request = {
        "tool_name": "get_secret",
        "service": "SecretsManager",
        "action": "GetSecretValue",
        "capability":
            "secretsmanager:GetSecretValue",
        "resource":
            "production-db-password",
        "arguments": {
            "secret_name":
                "production-db-password"
        },
    }

    enforce_action(
        session_id=session["session_id"],
        request=iam_request,
        allowed_services=ALLOWED_SERVICES,
        allowed_resources=ALLOWED_RESOURCES,
        identity_trusted=True,
        task_trusted=True,
    )

    result = enforce_action(
        session_id=session["session_id"],
        request=secret_request,
        allowed_services=ALLOWED_SERVICES,
        allowed_resources=ALLOWED_RESOURCES,
        identity_trusted=True,
        task_trusted=True,
    )

    assert result["decision"] == "BLOCK"

    events = read_audit_events()

    blocked_events = [
        event
        for event in events
        if event["decision"] == "BLOCK"
    ]

    assert len(blocked_events) == 1

    assert (
        blocked_events[0]["executed"]
        is False
    )

    assert (
        blocked_events[0][
            "blocked_capability"
        ]
        ==
        "secretsmanager:GetSecretValue"
    )


def test_audit_log_does_not_store_arguments():

    session = make_session()

    request = {
        "tool_name": "check_ec2",
        "service": "EC2",
        "action": "DescribeInstances",
        "capability": "ec2:DescribeInstances",
        "resource": "i-demo123",

        "arguments": {
            "instance_id": "i-demo123",
            "pretend_secret": "DO_NOT_LOG_THIS",
        },
    }

    enforce_action(
        session_id=session["session_id"],
        request=request,
        allowed_services=ALLOWED_SERVICES,
        allowed_resources=ALLOWED_RESOURCES,
        identity_trusted=True,
        task_trusted=True,
    )

    events = read_audit_events()

    assert len(events) == 1

    assert "arguments" not in events[0]

    assert (
        "DO_NOT_LOG_THIS"
        not in str(events[0])
    )