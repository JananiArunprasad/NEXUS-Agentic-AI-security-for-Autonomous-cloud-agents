from app.security.containment_planner import (
    plan_containment,
)

from app.security.observer import (
    observe_action,
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
    resource="demo-resource",
):

    observe_action(
        session_id,
        {
            "service": service,
            "action": action,
            "resource": resource,
        },
    )


def get_plan(
    session_id,
    identity_trusted=True,
    task_trusted=True,
):

    return plan_containment(
        session_id=session_id,

        allowed_services=
            ALLOWED_SERVICES,

        allowed_resources=
            ALLOWED_RESOURCES,

        identity_trusted=
            identity_trusted,

        task_trusted=
            task_trusted,
    )


def test_normal_session_requires_no_containment():

    session = make_session()

    add_action(
        session["session_id"],
        "EC2",
        "DescribeInstances",
        "i-demo123",
    )

    add_action(
        session["session_id"],
        "CloudWatch",
        "GetMetricData",
        "i-demo123",
    )

    result = get_plan(
        session["session_id"]
    )

    assert (
        result["containment_mode"]
        == "NONE"
    )

    assert result["restrict"] is None


def test_discovery_stage_blocks_next_credential_stage():

    session = make_session()

    add_action(
        session["session_id"],
        "IAM",
        "ListRoles",
        "aws-account",
    )

    result = get_plan(
        session["session_id"]
    )

    assert (
        result["containment_mode"]
        == "MINIMUM_CONTAINMENT"
    )

    assert (
        result["restrict"]["capability"]
        == "secretsmanager:GetSecretValue"
    )

    assert "EC2" in (
        result["preserve"]["services"]
    )

    assert "CloudWatch" in (
        result["preserve"]["services"]
    )


def test_credentials_stage_blocks_sensitive_s3():

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

    result = get_plan(
        session["session_id"]
    )

    assert (
        result["restrict"]["capability"]
        == "s3:GetObject"
    )


def test_collection_stage_blocks_exfiltration():

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
        (
            "company-sensitive-data/"
            "customer_records.csv"
        ),
    )

    result = get_plan(
        session["session_id"]
    )

    assert (
        result["restrict"]["capability"]
        == "external:SendData"
    )


def test_completed_chain_uses_exfiltration_cut_point():

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
        (
            "company-sensitive-data/"
            "customer_records.csv"
        ),
    )

    add_action(
        session["session_id"],
        "ExternalAPI",
        "SendData",
        "https://untrusted-example.test",
    )

    result = get_plan(
        session["session_id"]
    )

    assert (
        result["containment_mode"]
        == "MINIMUM_CONTAINMENT"
    )

    assert (
        result["restrict"]["capability"]
        == "external:SendData"
    )


def test_untrusted_identity_causes_full_quarantine():

    session = make_session()

    result = get_plan(
        session["session_id"],
        identity_trusted=False,
    )

    assert (
        result["containment_mode"]
        == "FULL_QUARANTINE"
    )

    assert (
        result["restrict"]["scope"]
        == "ALL_AGENT_CAPABILITIES"
    )

    assert (
        result["preserve"]["services"]
        == []
    )