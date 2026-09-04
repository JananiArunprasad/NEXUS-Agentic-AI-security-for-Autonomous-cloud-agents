import os

from datetime import (
    datetime,
    timedelta,
    timezone,
)

import boto3

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    NoRegionError,
    ProfileNotFound,
)

from dotenv import load_dotenv


# =========================================================
# ENVIRONMENT
# =========================================================

load_dotenv()


# =========================================================
# AWS SESSION
# =========================================================

def get_aws_session():
    """
    Create a Boto3 session using the configured
    AWS profile and region.

    NEXUS never stores AWS credentials in source code.
    """

    profile = os.getenv(
        "AWS_PROFILE"
    )

    region = os.getenv(
        "AWS_REGION"
    )

    session_arguments = {}

    if profile:

        session_arguments[
            "profile_name"
        ] = profile

    if region:

        session_arguments[
            "region_name"
        ] = region

    return boto3.Session(
        **session_arguments
    )


# =========================================================
# ACCOUNT MASKING
# =========================================================

def mask_account_id(
    account_id: str | None,
):
    """
    Avoid exposing the complete AWS account ID
    through the NEXUS dashboard/API.
    """

    if not account_id:

        return None

    if len(account_id) <= 4:

        return "****"

    hidden_length = (
        len(account_id) - 4
    )

    return (
        "*" * hidden_length
        + account_id[-4:]
    )


# =========================================================
# AWS STATUS
# =========================================================

def get_aws_status():
    """
    Verify AWS authentication using STS.

    This does not perform any cloud-agent workload.
    It only verifies that NEXUS has a valid AWS session.
    """

    try:

        session = get_aws_session()

        sts = session.client(
            "sts"
        )

        identity = (
            sts.get_caller_identity()
        )

        arn = identity.get(
            "Arn",
            "",
        )

        principal = (
            arn.split("/")[-1]
            if arn
            else "unknown"
        )

        return {
            "success": True,

            "connected": True,

            "backend": "AWS",

            "profile": (
                os.getenv(
                    "AWS_PROFILE"
                )
                or "default"
            ),

            "region": (
                session.region_name
                or os.getenv(
                    "AWS_REGION"
                )
            ),

            "account":
                mask_account_id(
                    identity.get(
                        "Account"
                    )
                ),

            "principal":
                principal,
        }

    except (
        NoCredentialsError,
        ProfileNotFound,
        NoRegionError,
        EndpointConnectionError,
        BotoCoreError,
        ClientError,
    ) as error:

        return {
            "success": False,

            "connected": False,

            "backend": "AWS",

            "error_type":
                type(error).__name__,

            "message": (
                "NEXUS could not establish "
                "an authenticated AWS session."
            ),
        }


# =========================================================
# REAL AWS EC2
# =========================================================

def aws_check_ec2(
    instance_id: str,
):
    """
    Perform a real read-only EC2 DescribeInstances call.
    """

    session = get_aws_session()

    ec2 = session.client(
        "ec2"
    )

    response = (
        ec2.describe_instances(
            InstanceIds=[
                instance_id
            ]
        )
    )

    instances = []

    for reservation in response.get(
        "Reservations",
        [],
    ):

        instances.extend(
            reservation.get(
                "Instances",
                [],
            )
        )

    if not instances:

        raise RuntimeError(
            "Configured EC2 sandbox "
            "instance was not found."
        )

    instance = instances[0]

    state = (
        instance.get(
            "State",
            {},
        ).get(
            "Name",
            "unknown",
        )
    )

    instance_type = (
        instance.get(
            "InstanceType",
            "unknown",
        )
    )

    availability_zone = (
        instance.get(
            "Placement",
            {},
        ).get(
            "AvailabilityZone",
            "unknown",
        )
    )

    return {
        "service":
            "EC2",

        "action":
            "DescribeInstances",

        "resource":
            instance_id,

        "message": (
            "Real AWS EC2 instance "
            f"{instance_id} is {state}."
        ),

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "backend":
            "AWS",

        "aws_data": {
            "state":
                state,

            "instance_type":
                instance_type,

            "availability_zone":
                availability_zone,
        },
    }


# =========================================================
# REAL AWS CLOUDWATCH
# =========================================================

def aws_read_cloudwatch(
    instance_id: str,
):
    """
    Retrieve recent EC2 CPUUtilization through the
    real CloudWatch GetMetricData API.
    """

    session = get_aws_session()

    cloudwatch = session.client(
        "cloudwatch"
    )

    end_time = datetime.now(
        timezone.utc
    )

    start_time = (
        end_time
        - timedelta(
            minutes=30
        )
    )

    response = (
        cloudwatch.get_metric_data(

            MetricDataQueries=[
                {
                    "Id":
                        "cpu",

                    "MetricStat": {
                        "Metric": {
                            "Namespace":
                                "AWS/EC2",

                            "MetricName":
                                "CPUUtilization",

                            "Dimensions": [
                                {
                                    "Name":
                                        "InstanceId",

                                    "Value":
                                        instance_id,
                                }
                            ],
                        },

                        "Period":
                            300,

                        "Stat":
                            "Average",
                    },

                    "ReturnData":
                        True,
                }
            ],

            StartTime=
                start_time,

            EndTime=
                end_time,

            ScanBy=
                "TimestampDescending",
        )
    )

    metric_results = response.get(
        "MetricDataResults",
        [],
    )

    latest_cpu = None

    if metric_results:

        values = (
            metric_results[0].get(
                "Values",
                [],
            )
        )

        if values:

            latest_cpu = round(
                float(
                    values[0]
                ),
                4,
            )

    if latest_cpu is None:

        message = (
            "Real CloudWatch request succeeded, "
            "but no recent CPU datapoint "
            "was available."
        )

    else:

        message = (
            "Real AWS CloudWatch "
            f"CPUUtilization: "
            f"{latest_cpu}%."
        )

    return {
        "service":
            "CloudWatch",

        "action":
            "GetMetricData",

        "resource":
            instance_id,

        "message":
            message,

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "backend":
            "AWS",

        "aws_data": {
            "metric":
                "CPUUtilization",

            "latest_average_percent":
                latest_cpu,
        },
    }


# =========================================================
# APPROVED REAL AWS TOOL GATEWAY
# =========================================================

def execute_aws_approved_request(
    request: dict,
):
    """
    Execute only explicitly supported read-only
    operations against real AWS.

    Dangerous capabilities have NO real implementation
    in this backend.
    """

    tool_name = request.get(
        "tool_name"
    )

    arguments = request.get(
        "arguments",
        {},
    )

    # -----------------------------------------------------
    # REAL EC2
    # -----------------------------------------------------

    if tool_name == "check_ec2":

        return aws_check_ec2(
            arguments[
                "instance_id"
            ]
        )

    # -----------------------------------------------------
    # REAL CLOUDWATCH
    # -----------------------------------------------------

    if tool_name == "read_cloudwatch":

        return aws_read_cloudwatch(
            arguments[
                "instance_id"
            ]
        )

    # -----------------------------------------------------
    # NOT IMPLEMENTED AGAINST REAL AWS
    # -----------------------------------------------------
    #
    # list_iam_roles
    # get_secret
    # read_s3
    # send_external
    #
    # Returning None causes the Enforcer to fail closed.

    return None