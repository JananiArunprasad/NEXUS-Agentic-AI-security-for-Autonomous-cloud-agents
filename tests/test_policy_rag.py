from app.security.policy_rag import (
    retrieve_policies,
)

from app.security.explanation_engine import (
    explain_enforcement_decision,
)


def test_policy_retrieval_returns_results():

    result = retrieve_policies(
        (
            "credential access using "
            "Secrets Manager after IAM discovery"
        )
    )

    assert result["success"] is True

    assert len(
        result["results"]
    ) > 0


def test_policy_result_contains_required_fields():

    result = retrieve_policies(
        "least privilege cloud agent"
    )

    first = result["results"][0]

    assert "policy_id" in first
    assert "title" in first
    assert "category" in first
    assert "source" in first
    assert "text" in first
    assert "similarity" in first


def test_block_explanation():

    request = {
        "service":
            "SecretsManager",

        "action":
            "GetSecretValue",

        "capability":
            "secretsmanager:GetSecretValue",

        "resource":
            "production-db-password",
    }

    enforcement_result = {
        "decision":
            "BLOCK",

        "executed":
            False,

        "reason": (
            "Requested capability matches "
            "the active minimum containment "
            "cut point."
        ),

        "blocked_capability":
            "secretsmanager:GetSecretValue",

        "containment_before": {
            "containment_mode":
                "MINIMUM_CONTAINMENT",

            "preserve": {
                "services": [
                    "EC2",
                    "CloudWatch",
                ],

                "resources": [
                    "i-demo123"
                ],
            },
        },
    }

    explanation = (
        explain_enforcement_decision(
            request,
            enforcement_result,
        )
    )

    assert (
        explanation["decision"]
        == "BLOCK"
    )

    assert (
        "secretsmanager:GetSecretValue"
        in explanation["summary"]
    )

    assert (
        explanation["containment_mode"]
        ==
        "MINIMUM_CONTAINMENT"
    )

    assert (
        "EC2"
        in explanation[
            "preserved_scope"
        ]["services"]
    )


def test_rag_does_not_change_decision():

    request = {
        "service": "EC2",
        "action": "DescribeInstances",
        "capability":
            "ec2:DescribeInstances",
        "resource": "i-demo123",
    }

    enforcement_result = {
        "decision": "ALLOW",
        "executed": True,
        "reason": (
            "Requested capability passed "
            "NEXUS enforcement."
        ),

        "containment_after": {
            "containment_mode": "NONE",

            "preserve": {
                "services": [
                    "EC2",
                    "CloudWatch",
                ],

                "resources": [
                    "i-demo123"
                ],
            },
        },
    }

    explanation = (
        explain_enforcement_decision(
            request,
            enforcement_result,
        )
    )

    assert (
        enforcement_result["decision"]
        == "ALLOW"
    )

    assert (
        explanation["decision"]
        == "ALLOW"
    )