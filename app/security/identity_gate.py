from app.agent.registry import get_agent_record


def verify_agent(
    agent_id: str,
    credential: str,
    task_id: str,
):
    """
    Verify agent identity and task authorization.
    """

    # STEP 1:
    # Does this agent exist?
    agent_record = get_agent_record(agent_id)

    if agent_record is None:
        return {
            "authorized": False,
            "decision": "QUARANTINE",
            "reason": "Unknown agent identity.",
        }

    # STEP 2:
    # Does the credential match?
    if credential != agent_record["credential"]:
        return {
            "authorized": False,
            "decision": "QUARANTINE",
            "reason": "Invalid agent credential.",
        }

    # STEP 3:
    # Is the requested task approved?
    approved_tasks = agent_record["approved_tasks"]

    if task_id not in approved_tasks:
        return {
            "authorized": False,
            "decision": "BLOCK",
            "reason": "Task is not authorized for this agent.",
        }

    # STEP 4:
    # Everything passed.
    task_record = approved_tasks[task_id]

    return {
        "authorized": True,
        "decision": "ALLOW",
        "reason": "Agent identity and task verified.",
        "agent_id": agent_id,
        "task_id": task_id,
        "task": task_record["description"],
        "allowed_services": task_record["allowed_services"],
        "allowed_resources": task_record["allowed_resources"],
    }