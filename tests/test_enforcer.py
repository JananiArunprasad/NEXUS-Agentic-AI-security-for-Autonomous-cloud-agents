from app.security.enforcer import (
    enforce_action,
)

from app.security.session_state import (
    create_session,
    get_session,
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


def make_session():

    return create_session(
        agent_id="CloudOps-Agent-01",
        task_id="task-ec2-troubleshoot",
        task_description="Diagnose EC2 high CPU",
    )


def enforce(
    session_id,
    request,
):

    return enforce_action(
        session_id=session_id,

        request=request,

        allowed_services=
            ALLOWED_SERVICES,

        allowed_resources=
            ALLOWED_RESOURCES,

        identity_trusted=True,

        task_trusted=True,
    )


def test_normal_ec2_request_executes():

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

    result = enforce(
        session["session_id"],
        request,
    )

    assert result["decision"] == "ALLOW"

    assert result["executed"] is True


def test_iam_stage_creates_future_containment():

    session = make_session()

    iam_request = {
        "tool_name": "list_iam_roles",
        "service": "IAM",
        "action": "ListRoles",
        "capability": "iam:ListRoles",
        "resource": "aws-account",
        "arguments": {},
    }

    result = enforce(
        session["session_id"],
        iam_request,
    )

    assert result["decision"] == "ALLOW"

    assert result["executed"] is True

    assert (
        result["containment_after"]
        ["restrict"]
        ["capability"]
        ==
        "secretsmanager:GetSecretValue"
    )


def test_secret_request_is_blocked_before_execution():

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

    enforce(
        session["session_id"],
        iam_request,
    )

    result = enforce(
        session["session_id"],
        secret_request,
    )

    assert result["decision"] == "BLOCK"

    assert result["executed"] is False

    assert (
        result["blocked_capability"]
        ==
        "secretsmanager:GetSecretValue"
    )

    stored_session = get_session(
        session["session_id"]
    )

    events = [
        action["event"]
        for action in stored_session["actions"]
    ]

    assert (
        "SecretsManager:GetSecretValue"
        not in events
    )


def test_safe_action_still_works_after_block():

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

    safe_request = {
        "tool_name":
            "read_application_logs",

        "service":
            "CloudWatch",

        "action":
            "GetLogEvents",

        "capability":
            "cloudwatch:GetLogEvents",

        "resource":
            "i-demo123",

        "arguments": {
            "instance_id":
                "i-demo123"
        },
    }

    enforce(
        session["session_id"],
        iam_request,
    )

    blocked = enforce(
        session["session_id"],
        secret_request,
    )

    assert blocked["executed"] is False

    safe_result = enforce(
        session["session_id"],
        safe_request,
    )

    assert safe_result["decision"] == "ALLOW"

    assert safe_result["executed"] is True