from app.security.observer import observe_action

from app.security.risk_engine import (
    evaluate_session_risk,
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


def add_action(
    session_id,
    service,
    action,
    resource,
):

    observe_action(
        session_id,
        {
            "service": service,
            "action": action,
            "resource": resource,
        },
    )


def get_risk(session_id):

    return evaluate_session_risk(
        session_id=session_id,
        allowed_services=ALLOWED_SERVICES,
        allowed_resources=ALLOWED_RESOURCES,
    )


def test_normal_ec2_action_has_no_risk():

    session = make_session()

    add_action(
        session["session_id"],
        "EC2",
        "DescribeInstances",
        "i-demo123",
    )

    result = get_risk(
        session["session_id"]
    )

    assert result["score"] == 0
    assert result["risk_level"] == "NONE"


def test_iam_discovery_increases_risk():

    session = make_session()

    add_action(
        session["session_id"],
        "IAM",
        "ListRoles",
        "aws-account",
    )

    result = get_risk(
        session["session_id"]
    )

    assert result["score"] == 30

    assert result["risk_level"] == (
        "MEDIUM"
    )


def test_credentials_after_discovery_are_high_risk():

    session = make_session()

    add_action(
        session["session_id"],
        "IAM",
        "ListRoles",
        "aws-account",
    )

    add_action(
        session["session_id"],
        "SecretsManager",
        "GetSecretValue",
        "production-db-password",
    )

    result = get_risk(
        session["session_id"]
    )

    assert result["score"] == 65

    assert result["risk_level"] == (
        "HIGH"
    )


def test_sensitive_s3_progression_is_high_risk():

    session = make_session()

    add_action(
        session["session_id"],
        "IAM",
        "ListRoles",
        "aws-account",
    )

    add_action(
        session["session_id"],
        "SecretsManager",
        "GetSecretValue",
        "production-db-password",
    )

    add_action(
        session["session_id"],
        "S3",
        "GetObject",
        "company-sensitive-data/customer_records.csv",
    )

    result = get_risk(
        session["session_id"]
    )

    assert result["score"] == 70

    assert result["risk_level"] == (
        "HIGH"
    )


def test_complete_exfiltration_chain_is_critical():

    session = make_session()

    add_action(
        session["session_id"],
        "IAM",
        "ListRoles",
        "aws-account",
    )

    add_action(
        session["session_id"],
        "SecretsManager",
        "GetSecretValue",
        "production-db-password",
    )

    add_action(
        session["session_id"],
        "S3",
        "GetObject",
        "company-sensitive-data/customer_records.csv",
    )

    add_action(
        session["session_id"],
        "ExternalAPI",
        "SendData",
        "https://untrusted-example.test",
    )

    result = get_risk(
        session["session_id"]
    )

    assert result["score"] == 90

    assert result["risk_level"] == (
        "CRITICAL"
    )