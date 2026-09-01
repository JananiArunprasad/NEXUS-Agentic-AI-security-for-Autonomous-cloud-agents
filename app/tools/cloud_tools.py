from datetime import datetime, timezone


def create_tool_result(service, action, resource, message):
    """
    Creates a standard result format for every simulated cloud action.
    """

    return {
        "service": service,
        "action": action,
        "resource": resource,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def check_ec2(instance_id: str):
    return create_tool_result(
        service="EC2",
        action="DescribeInstances",
        resource=instance_id,
        message=f"Retrieved information for EC2 instance {instance_id}.",
    )


def read_cloudwatch(instance_id: str):
    return create_tool_result(
        service="CloudWatch",
        action="GetMetricData",
        resource=instance_id,
        message=f"Retrieved CPU metrics for {instance_id}.",
    )


def read_application_logs(instance_id: str):
    return create_tool_result(
        service="CloudWatch",
        action="GetLogEvents",
        resource=instance_id,
        message=f"Retrieved application logs for {instance_id}.",
    )


def list_iam_roles():
    return create_tool_result(
        service="IAM",
        action="ListRoles",
        resource="aws-account",
        message="Retrieved available IAM roles.",
    )


def get_secret(secret_name: str):
    return create_tool_result(
        service="SecretsManager",
        action="GetSecretValue",
        resource=secret_name,
        message=f"Retrieved secret {secret_name}.",
    )


def read_s3(bucket: str, object_name: str):
    return create_tool_result(
        service="S3",
        action="GetObject",
        resource=f"{bucket}/{object_name}",
        message=f"Retrieved {object_name} from {bucket}.",
    )


def send_external(destination: str):
    return create_tool_result(
        service="ExternalAPI",
        action="SendData",
        resource=destination,
        message=f"Attempted to send data to {destination}.",
    )