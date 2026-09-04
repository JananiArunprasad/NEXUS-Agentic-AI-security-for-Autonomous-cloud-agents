import os


# =========================================================
# DEFAULT DEMO VALUES
# =========================================================

DEFAULT_INSTANCE_ID = os.getenv(
    "NEXUS_DEMO_INSTANCE_ID",
    "i-demo123",
)

DEFAULT_SECRET = (
    "production-db-password"
)

DEFAULT_BUCKET = (
    "company-sensitive-data"
)

DEFAULT_OBJECT = (
    "customer_records.csv"
)

DEFAULT_EXTERNAL_DESTINATION = (
    "https://untrusted-example.test"
)


# =========================================================
# SUPPORTED AGENT TOOLS
# =========================================================

SUPPORTED_TOOLS = {
    "check_ec2",
    "read_cloudwatch",
    "read_application_logs",
    "list_iam_roles",
    "get_secret",
    "read_s3",
    "send_external",
}


# =========================================================
# BUILD TRUSTED STRUCTURED REQUEST
# =========================================================

def build_tool_request(
    tool_name: str,
    arguments: dict | None = None,
):
    """
    Convert a planner-selected tool into the canonical
    request format expected by NEXUS.

    The LLM does NOT get to invent service names,
    capabilities or action names.
    """

    arguments = arguments or {}

    # -----------------------------------------------------
    # EC2
    # -----------------------------------------------------

    if tool_name == "check_ec2":

        instance_id = arguments.get(
            "instance_id",
            DEFAULT_INSTANCE_ID,
        )

        return {
            "tool_name": "check_ec2",
            "service": "EC2",
            "action": "DescribeInstances",
            "capability": "ec2:DescribeInstances",
            "resource": instance_id,
            "arguments": {
                "instance_id":
                    instance_id,
            },
        }

    # -----------------------------------------------------
    # CLOUDWATCH METRICS
    # -----------------------------------------------------

    if tool_name == "read_cloudwatch":

        instance_id = arguments.get(
            "instance_id",
            DEFAULT_INSTANCE_ID,
        )

        return {
            "tool_name":
                "read_cloudwatch",

            "service":
                "CloudWatch",

            "action":
                "GetMetricData",

            "capability":
                "cloudwatch:GetMetricData",

            "resource":
                instance_id,

            "arguments": {
                "instance_id":
                    instance_id,
            },
        }

    # -----------------------------------------------------
    # CLOUDWATCH LOGS
    # -----------------------------------------------------

    if tool_name == "read_application_logs":

        instance_id = arguments.get(
            "instance_id",
            DEFAULT_INSTANCE_ID,
        )

        return {
            "tool_name":
                "read_application_logs",

            "service":
                "CloudWatch",

            "action":
                "GetLogEvents",

            "capability":
                "cloudwatch:GetLogEvents",

            "resource":
                instance_id,

            "arguments": {
                "instance_id":
                    instance_id,
            },
        }

    # -----------------------------------------------------
    # IAM
    # -----------------------------------------------------

    if tool_name == "list_iam_roles":

        return {
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

    # -----------------------------------------------------
    # SECRETS MANAGER
    # -----------------------------------------------------

    if tool_name == "get_secret":

        secret_name = arguments.get(
            "secret_name",
            DEFAULT_SECRET,
        )

        return {
            "tool_name":
                "get_secret",

            "service":
                "SecretsManager",

            "action":
                "GetSecretValue",

            "capability":
                "secretsmanager:GetSecretValue",

            "resource":
                secret_name,

            "arguments": {
                "secret_name":
                    secret_name,
            },
        }

    # -----------------------------------------------------
    # S3
    # -----------------------------------------------------

    if tool_name == "read_s3":

        bucket = arguments.get(
            "bucket",
            DEFAULT_BUCKET,
        )

        object_name = arguments.get(
            "object_name",
            DEFAULT_OBJECT,
        )

        return {
            "tool_name":
                "read_s3",

            "service":
                "S3",

            "action":
                "GetObject",

            "capability":
                "s3:GetObject",

            "resource":
                f"{bucket}/{object_name}",

            "arguments": {
                "bucket":
                    bucket,

                "object_name":
                    object_name,
            },
        }

    # -----------------------------------------------------
    # EXTERNAL DESTINATION
    # -----------------------------------------------------

    if tool_name == "send_external":

        destination = arguments.get(
            "destination",
            DEFAULT_EXTERNAL_DESTINATION,
        )

        return {
            "tool_name":
                "send_external",

            "service":
                "ExternalAPI",

            "action":
                "SendData",

            "capability":
                "external:SendData",

            "resource":
                destination,

            "arguments": {
                "destination":
                    destination,
            },
        }

    # -----------------------------------------------------
    # UNKNOWN TOOL
    # -----------------------------------------------------

    return None