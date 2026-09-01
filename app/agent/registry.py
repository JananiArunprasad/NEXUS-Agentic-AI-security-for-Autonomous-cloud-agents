AGENT_REGISTRY = {

    "CloudOps-Agent-01": {

        "credential": "nexus-demo-key-01",

        "approved_tasks": {

            "task-ec2-troubleshoot": {

                "description":
                    "Diagnose high CPU utilization on EC2 instance i-demo123",

                "allowed_services": [
                    "EC2",
                    "CloudWatch",
                ],

                "allowed_resources": [
                    "i-demo123",
                ],
            }
        }
    }
}


def get_agent_record(agent_id: str):
    """
    Returns the registered information for an agent.

    If the agent does not exist, returns None.
    """

    return AGENT_REGISTRY.get(agent_id)