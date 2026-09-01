from fastapi import FastAPI

from app.agent.simulator import CloudOpsAgent
from app.security.identity_gate import verify_agent


app = FastAPI(
    title="NEXUS",
    description="Adaptive Attack-Chain Defense for Autonomous Cloud Agents",
    version="0.5.0",
)


@app.get("/")
def root():
    return {
        "project": "NEXUS",
        "status": "running",
        "version": "0.5.0",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.get("/demo/normal")
def run_normal_demo():

    verification = verify_agent(
        agent_id="CloudOps-Agent-01",
        credential="nexus-demo-key-01",
        task_id="task-ec2-troubleshoot",
    )

    if not verification["authorized"]:
        return verification

    agent = CloudOpsAgent(
        agent_id="CloudOps-Agent-01",
        task=verification["task"],
    )

    result = agent.run_normal_task()

    return {
        "verification": verification,
        "execution": result,
    }


@app.get("/demo/attack")
def run_attack_demo():

    verification = verify_agent(
        agent_id="CloudOps-Agent-01",
        credential="nexus-demo-key-01",
        task_id="task-ec2-troubleshoot",
    )

    if not verification["authorized"]:
        return verification

    agent = CloudOpsAgent(
        agent_id="CloudOps-Agent-01",
        task=verification["task"],
    )

    result = agent.run_attack_scenario()

    return {
        "verification": verification,
        "execution": result,
    }


@app.get("/demo/unauthorized")
def run_unauthorized_demo():

    verification = verify_agent(
        agent_id="Unknown-Agent-99",
        credential="fake-key",
        task_id="task-ec2-troubleshoot",
    )

    return verification
@app.get("/demo/document/safe")
def run_safe_document_demo():

    verification = verify_agent(
        agent_id="CloudOps-Agent-01",
        credential="nexus-demo-key-01",
        task_id="task-ec2-troubleshoot",
    )

    if not verification["authorized"]:
        return verification

    agent = CloudOpsAgent(
        agent_id="CloudOps-Agent-01",
        task=verification["task"],
    )

    return agent.read_document(
        "safe_ec2_runbook.txt"
    )


@app.get("/demo/document/malicious")
def run_malicious_document_demo():

    verification = verify_agent(
        agent_id="CloudOps-Agent-01",
        credential="nexus-demo-key-01",
        task_id="task-ec2-troubleshoot",
    )

    if not verification["authorized"]:
        return verification

    agent = CloudOpsAgent(
        agent_id="CloudOps-Agent-01",
        task=verification["task"],
    )

    return agent.read_document(
        "malicious_ec2_runbook.txt"
    )

@app.get("/demo/document/paraphrased")
def run_paraphrased_document_demo():

    verification = verify_agent(
        agent_id="CloudOps-Agent-01",
        credential="nexus-demo-key-01",
        task_id="task-ec2-troubleshoot",
    )

    if not verification["authorized"]:
        return verification

    agent = CloudOpsAgent(
        agent_id="CloudOps-Agent-01",
        task=verification["task"],
    )

    return agent.read_document(
        "paraphrased_attack.txt"
    )
@app.get("/demo/document/ambiguous")
def run_ambiguous_document_demo():

    verification = verify_agent(
        agent_id="CloudOps-Agent-01",
        credential="nexus-demo-key-01",
        task_id="task-ec2-troubleshoot",
    )

    if not verification["authorized"]:
        return verification

    agent = CloudOpsAgent(
        agent_id="CloudOps-Agent-01",
        task=verification["task"],
    )

    return agent.read_document(
        "ambiguous_reference.txt"
    )