from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from pydantic import (
    BaseModel,
    Field,
)


# =========================================================
# NEXUS AGENT
# =========================================================

from app.agent.simulator import (
    CloudOpsAgent,
)

from app.agent.interactive_runner import (
    run_interactive_task,
)


# =========================================================
# IDENTITY + TASK VERIFICATION
# =========================================================

from app.security.identity_gate import (
    verify_agent,
)


# =========================================================
# RUNTIME SESSION + OBSERVER
# =========================================================

from app.security.session_state import (
    create_session,
    get_session,
)

from app.security.observer import (
    observe_action,
)


# =========================================================
# ATTACK-CHAIN ENGINE
# =========================================================

from app.security.attack_chain import (
    analyze_session,
)


# =========================================================
# RISK ENGINE
# =========================================================

from app.security.risk_engine import (
    evaluate_session_risk,
)


# =========================================================
# MINIMUM CONTAINMENT PLANNER
# =========================================================

from app.security.containment_planner import (
    plan_containment,
)


# =========================================================
# PRE-ACTION ENFORCER
# =========================================================

from app.security.enforcer import (
    enforce_action,
)


# =========================================================
# AUDIT LOGGER
# =========================================================

from app.audit.logger import (
    read_audit_events,
)


# =========================================================
# POLICY RAG + EXPLANATION
# =========================================================

from app.security.policy_rag import (
    retrieve_policies,
)

from app.security.explanation_engine import (
    explain_enforcement_decision,
)


# =========================================================
# EVALUATION
# =========================================================

from app.evaluation.evaluator import (
    run_evaluation,
    read_latest_evaluation,
)

from app.cloud.aws_backend import (
    get_aws_status,
)
# =========================================================
# FASTAPI APPLICATION
# =========================================================

app = FastAPI(
    title="NEXUS",
    description=(
        "Adaptive Attack-Chain Defense "
        "for Autonomous Cloud Agents"
    ),
    version="1.0.0",
)


# =========================================================
# INTERACTIVE AGENT REQUEST MODEL
# =========================================================

class AgentTaskRequest(BaseModel):

    task: str = Field(
        ...,
        min_length=1,
        max_length=1000,
    )


# =========================================================
# BASIC ROUTES
# =========================================================

@app.get("/")
def root():
    """
    Basic NEXUS application status.
    """

    return {
        "project": "NEXUS",

        "description": (
            "Adaptive Attack-Chain Defense "
            "for Autonomous Cloud Agents"
        ),

        "status": "running",

        "version": "1.0.0",

        "execution_mode": "SIMULATION",

        "dashboard": "/dashboard",
    }


@app.get("/health")
def health():
    """
    Simple health check.
    """

    return {
        "status": "healthy"
    }


# =========================================================
# BASIC NORMAL AGENT DEMO
# =========================================================

@app.get("/demo/normal")
def run_normal_demo():
    """
    Run the original legitimate simulated
    cloud-agent workflow.
    """

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


# =========================================================
# BASIC ATTACK DEMO
# =========================================================

@app.get("/demo/attack")
def run_attack_demo():
    """
    Run the original simulated malicious workflow.

    This endpoint is intentionally NOT pre-action protected.

    It serves as a monitor-only baseline for comparison
    against the enforced NEXUS workflow.
    """

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


# =========================================================
# UNAUTHORIZED AGENT DEMO
# =========================================================

@app.get("/demo/unauthorized")
def run_unauthorized_demo():
    """
    Demonstrate rejection of an unknown agent.
    """

    verification = verify_agent(
        agent_id="Unknown-Agent-99",
        credential="fake-key",
        task_id="task-ec2-troubleshoot",
    )

    return verification


# =========================================================
# SAFE DOCUMENT DEMO
# =========================================================

@app.get("/demo/document/safe")
def run_safe_document_demo():
    """
    Process a safe troubleshooting document through
    the NEXUS multi-tier content-security pipeline.
    """

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


# =========================================================
# MALICIOUS DOCUMENT DEMO
# =========================================================

@app.get("/demo/document/malicious")
def run_malicious_document_demo():
    """
    Demonstrate detection of an obvious
    indirect prompt-injection document.
    """

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


# =========================================================
# PARAPHRASED ATTACK DOCUMENT
# =========================================================

@app.get("/demo/document/paraphrased")
def run_paraphrased_document_demo():
    """
    Demonstrate Tier-2 semantic detection of
    paraphrased malicious content.
    """

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


# =========================================================
# AMBIGUOUS / TIER-3 DOCUMENT
# =========================================================

@app.get("/demo/document/ambiguous")
def run_ambiguous_document_demo():
    """
    Demonstrate ambiguous content that may require
    Tier-3 local LLM classification.
    """

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


# =========================================================
# RUNTIME NORMAL SESSION
# =========================================================

@app.get("/demo/runtime/normal")
def run_runtime_normal_demo():
    """
    Observe a legitimate cloud workflow and evaluate:

    - attack-chain progression
    - risk
    - containment
    """

    # -----------------------------------------------------
    # Verify agent
    # -----------------------------------------------------

    verification = verify_agent(
        agent_id="CloudOps-Agent-01",
        credential="nexus-demo-key-01",
        task_id="task-ec2-troubleshoot",
    )

    if not verification["authorized"]:
        return verification

    # -----------------------------------------------------
    # Create runtime session
    # -----------------------------------------------------

    session = create_session(
        agent_id="CloudOps-Agent-01",
        task_id="task-ec2-troubleshoot",
        task_description=verification["task"],
    )

    session_id = session[
        "session_id"
    ]

    # -----------------------------------------------------
    # Run simulated agent
    # -----------------------------------------------------

    agent = CloudOpsAgent(
        agent_id="CloudOps-Agent-01",
        task=verification["task"],
    )

    execution = agent.run_normal_task()

    security_timeline = []

    # -----------------------------------------------------
    # Analyze every executed action
    # -----------------------------------------------------

    for action in execution["actions"]:

        observer_result = observe_action(
            session_id,
            action,
        )

        attack_analysis = analyze_session(
            session_id
        )

        risk_analysis = evaluate_session_risk(
            session_id=session_id,

            allowed_services=verification[
                "allowed_services"
            ],

            allowed_resources=verification[
                "allowed_resources"
            ],
        )

        containment_plan = plan_containment(
            session_id=session_id,

            allowed_services=verification[
                "allowed_services"
            ],

            allowed_resources=verification[
                "allowed_resources"
            ],

            identity_trusted=True,
            task_trusted=True,
        )

        security_timeline.append(
            {
                "sequence":
                    observer_result[
                        "recorded_action"
                    ]["sequence"],

                "event":
                    observer_result[
                        "recorded_action"
                    ]["event"],

                "attack_analysis":
                    attack_analysis[
                        "most_advanced_chain"
                    ],

                "risk":
                    risk_analysis,

                "containment":
                    containment_plan,
            }
        )

    # -----------------------------------------------------
    # Final state
    # -----------------------------------------------------

    final_attack_analysis = analyze_session(
        session_id
    )

    final_risk = evaluate_session_risk(
        session_id=session_id,

        allowed_services=verification[
            "allowed_services"
        ],

        allowed_resources=verification[
            "allowed_resources"
        ],
    )

    final_containment = plan_containment(
        session_id=session_id,

        allowed_services=verification[
            "allowed_services"
        ],

        allowed_resources=verification[
            "allowed_resources"
        ],

        identity_trusted=True,
        task_trusted=True,
    )

    return {
        "verification":
            verification,

        "session":
            get_session(
                session_id
            ),

        "security_timeline":
            security_timeline,

        "final_attack_analysis":
            final_attack_analysis,

        "final_risk":
            final_risk,

        "final_containment":
            final_containment,
    }


# =========================================================
# RUNTIME ATTACK — MONITOR-ONLY BASELINE
# =========================================================

@app.get("/demo/runtime/attack")
def run_runtime_attack_demo():
    """
    Run the original attack sequence and analyze
    it AFTER each simulated action.

    This represents the monitor-only baseline.

    Compare against:
        /demo/runtime/enforced-attack
    """

    verification = verify_agent(
        agent_id="CloudOps-Agent-01",
        credential="nexus-demo-key-01",
        task_id="task-ec2-troubleshoot",
    )

    if not verification["authorized"]:
        return verification

    session = create_session(
        agent_id="CloudOps-Agent-01",
        task_id="task-ec2-troubleshoot",
        task_description=verification["task"],
    )

    session_id = session[
        "session_id"
    ]

    agent = CloudOpsAgent(
        agent_id="CloudOps-Agent-01",
        task=verification["task"],
    )

    execution = agent.run_attack_scenario()

    security_timeline = []

    for action in execution["actions"]:

        observer_result = observe_action(
            session_id,
            action,
        )

        attack_analysis = analyze_session(
            session_id
        )

        risk_analysis = evaluate_session_risk(
            session_id=session_id,

            allowed_services=verification[
                "allowed_services"
            ],

            allowed_resources=verification[
                "allowed_resources"
            ],
        )

        containment_plan = plan_containment(
            session_id=session_id,

            allowed_services=verification[
                "allowed_services"
            ],

            allowed_resources=verification[
                "allowed_resources"
            ],

            identity_trusted=True,
            task_trusted=True,
        )

        security_timeline.append(
            {
                "sequence":
                    observer_result[
                        "recorded_action"
                    ]["sequence"],

                "event":
                    observer_result[
                        "recorded_action"
                    ]["event"],

                "attack_analysis":
                    attack_analysis[
                        "most_advanced_chain"
                    ],

                "risk":
                    risk_analysis,

                "containment":
                    containment_plan,
            }
        )

    final_attack_analysis = analyze_session(
        session_id
    )

    final_risk = evaluate_session_risk(
        session_id=session_id,

        allowed_services=verification[
            "allowed_services"
        ],

        allowed_resources=verification[
            "allowed_resources"
        ],
    )

    final_containment = plan_containment(
        session_id=session_id,

        allowed_services=verification[
            "allowed_services"
        ],

        allowed_resources=verification[
            "allowed_resources"
        ],

        identity_trusted=True,
        task_trusted=True,
    )

    return {
        "verification":
            verification,

        "session":
            get_session(
                session_id
            ),

        "security_timeline":
            security_timeline,

        "final_attack_analysis":
            final_attack_analysis,

        "final_risk":
            final_risk,

        "final_containment":
            final_containment,
    }


# =========================================================
# PRE-ACTION ENFORCED ATTACK
# =========================================================

@app.get("/demo/runtime/enforced-attack")
def run_enforced_attack_demo():
    """
    Demonstrate true pre-action NEXUS enforcement.

    The agent proposes actions first.

    NEXUS evaluates each request BEFORE simulated
    execution is permitted.
    """

    # -----------------------------------------------------
    # Verify identity + approved task
    # -----------------------------------------------------

    verification = verify_agent(
        agent_id="CloudOps-Agent-01",
        credential="nexus-demo-key-01",
        task_id="task-ec2-troubleshoot",
    )

    if not verification["authorized"]:
        return verification

    # -----------------------------------------------------
    # Create runtime session
    # -----------------------------------------------------

    session = create_session(
        agent_id="CloudOps-Agent-01",
        task_id="task-ec2-troubleshoot",
        task_description=verification["task"],
    )

    session_id = session[
        "session_id"
    ]

    # -----------------------------------------------------
    # Agent generates proposed requests
    # -----------------------------------------------------

    agent = CloudOpsAgent(
        agent_id="CloudOps-Agent-01",
        task=verification["task"],
    )

    requests = (
        agent.get_attack_action_requests()
    )

    enforcement_timeline = []

    blocked_request = None

    # -----------------------------------------------------
    # NEXUS evaluates each proposed action
    # -----------------------------------------------------

    for request in requests:

        result = enforce_action(
            session_id=session_id,

            request=request,

            allowed_services=verification[
                "allowed_services"
            ],

            allowed_resources=verification[
                "allowed_resources"
            ],

            identity_trusted=True,

            task_trusted=True,
        )

        # -------------------------------------------------
        # Policy-supported explanation
        # -------------------------------------------------

        result["explanation"] = (
            explain_enforcement_decision(
                request=request,
                enforcement_result=result,
            )
        )

        enforcement_timeline.append(
            result
        )

        # -------------------------------------------------
        # Stop malicious chain after security intervention
        # -------------------------------------------------

        if result["decision"] in {
            "BLOCK",
            "HOLD",
            "DENY",
        }:

            blocked_request = request

            break

    # -----------------------------------------------------
    # Demonstrate legitimate recovery
    # -----------------------------------------------------

    recovery_request = (
        agent.get_safe_recovery_request()
    )

    recovery_result = enforce_action(
        session_id=session_id,

        request=recovery_request,

        allowed_services=verification[
            "allowed_services"
        ],

        allowed_resources=verification[
            "allowed_resources"
        ],

        identity_trusted=True,

        task_trusted=True,
    )

    recovery_result["explanation"] = (
        explain_enforcement_decision(
            request=recovery_request,
            enforcement_result=recovery_result,
        )
    )

    # -----------------------------------------------------
    # Final result
    # -----------------------------------------------------

    return {
        "verification":
            verification,

        "session":
            get_session(
                session_id
            ),

        "enforcement_timeline":
            enforcement_timeline,

        "blocked_request":
            blocked_request,

        "safe_task_recovery":
            recovery_result,

        "final_attack_analysis":
            analyze_session(
                session_id
            ),

        "final_risk":
            evaluate_session_risk(
                session_id=session_id,

                allowed_services=verification[
                    "allowed_services"
                ],

                allowed_resources=verification[
                    "allowed_resources"
                ],
            ),

        "final_containment":
            plan_containment(
                session_id=session_id,

                allowed_services=verification[
                    "allowed_services"
                ],

                allowed_resources=verification[
                    "allowed_resources"
                ],

                identity_trusted=True,

                task_trusted=True,
            ),
    }


# =========================================================
# AUDIT LOGGER API
# =========================================================

@app.get("/audit/recent")
def get_recent_audit_events():
    """
    Return the newest NEXUS security audit events.
    """

    return {
        "events": read_audit_events(
            limit=50
        )
    }


# =========================================================
# POLICY RAG API
# =========================================================

@app.get("/policy/search")
def search_security_policy(
    q: str,
):
    """
    Retrieve relevant security-policy controls
    from the NEXUS policy knowledge base.
    """

    return retrieve_policies(
        query=q,
        n_results=3,
    )


# =========================================================
# EVALUATION
# =========================================================

@app.get("/evaluation/run")
def run_nexus_evaluation():
    """
    Execute the NEXUS core runtime-security benchmark.
    """

    return run_evaluation()


@app.get("/evaluation/latest")
def get_latest_nexus_evaluation():
    """
    Return the latest saved NEXUS benchmark report.
    """

    return read_latest_evaluation()


# =========================================================
# INTERACTIVE AUTONOMOUS CLOUD AGENT
# =========================================================

@app.post("/agent/execute")
def execute_interactive_agent_task(
    payload: AgentTaskRequest,
):
    """
    Accept a natural-language task for the autonomous
    cloud agent.

    Flow:

        User task
            ↓
        AI Agent Planner
            ↓
        Structured proposed tool calls
            ↓
        NEXUS pre-action Enforcer
            ↓
        ALLOW / BLOCK
            ↓
        Simulator

    Phase 17 will replace selected simulator operations
    with approved real AWS calls.
    """

    return run_interactive_task(
        payload.task
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.get(
    "/dashboard",
    include_in_schema=False,
)
def get_nexus_dashboard():
    """
    Serve the NEXUS Security Operations Dashboard.
    """

    dashboard_file = (
        Path(__file__).resolve().parent
        / "dashboard"
        / "dashboard.html"
    )

    return FileResponse(
        dashboard_file
    )
# =========================================================
# AWS CONNECTIVITY
# =========================================================

@app.get("/aws/status")
def get_nexus_aws_status():
    """
    Return the current NEXUS AWS connection state.

    No cloud-agent action is executed here.
    """

    return get_aws_status()