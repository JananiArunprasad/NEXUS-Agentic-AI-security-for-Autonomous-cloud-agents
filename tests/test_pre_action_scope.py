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


def make_session():

    return create_session(
        agent_id="CloudOps-Agent-01",
        task_id="task-ec2-troubleshoot",
        task_description="Diagnose EC2 high CPU",
    )


def test_direct_secret_request_is_blocked():

    session = make_session()

    request = {
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

    assert (
        result["decision"]
        == "BLOCK"
    )

    assert (
        result["executed"]
        is False
    )


def test_iam_discovery_can_be_monitored():

    session = make_session()

    request = {
        "tool_name":
            "list_iam_roles",

        "service":
            "IAM",

        "action":
            "ListRoles",

        "capability":
            "iam:ListRoles",

        "resource":
            "aws-account",

        "arguments": {},
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

    assert (
        result["decision"]
        == "ALLOW"
    )

    assert (
        result["executed"]
        is True
    )