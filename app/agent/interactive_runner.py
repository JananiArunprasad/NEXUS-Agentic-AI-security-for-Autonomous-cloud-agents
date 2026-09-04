from app.agent.interactive_planner import (
    plan_user_task,
)

from app.security.identity_gate import (
    verify_agent,
)

from app.security.session_state import (
    create_session,
    get_session,
)

from app.security.enforcer import (
    enforce_action,
)

from app.security.attack_chain import (
    analyze_session,
)

from app.security.risk_engine import (
    evaluate_session_risk,
)

from app.security.containment_planner import (
    plan_containment,
)

from app.security.explanation_engine import (
    explain_enforcement_decision,
)


# =========================================================
# INTERACTIVE AGENT RUNNER
# =========================================================

def run_interactive_task(
    task: str,
):
    """
    Execute one natural-language cloud-agent task through
    the full NEXUS runtime-security pipeline.

    Phase 16.5 uses simulated cloud tools.

    Phase 17 will swap in the AWS executor.
    """

    task = task.strip()

    if not task:

        return {
            "success": False,
            "error": "Task cannot be empty.",
        }


    # =====================================================
    # IDENTITY + TASK VERIFICATION
    # =====================================================

    verification = verify_agent(
        agent_id="CloudOps-Agent-01",
        credential="nexus-demo-key-01",
        task_id="task-ec2-troubleshoot",
    )


    if not verification[
        "authorized"
    ]:

        return {
            "success": False,
            "verification": verification,
        }


    # =====================================================
    # CREATE RUNTIME SESSION
    # =====================================================

    session = create_session(
        agent_id="CloudOps-Agent-01",
        task_id="task-ec2-troubleshoot",
        task_description=verification[
            "task"
        ],
    )


    session_id = session[
        "session_id"
    ]


    # =====================================================
    # AI AGENT PLANNING
    # =====================================================

    plan = plan_user_task(
        task
    )


    if not plan[
        "success"
    ]:

        return {
            "success": False,
            "verification": verification,
            "plan": plan,
        }


    timeline = []

    final_decision = "COMPLETED"


    # =====================================================
    # PRE-ACTION NEXUS ENFORCEMENT
    # =====================================================

    for request in plan[
        "requests"
    ]:

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


        # -----------------------------------------------
        # Explain decision using Policy RAG
        # -----------------------------------------------

        result[
            "explanation"
        ] = explain_enforcement_decision(
            request=request,
            enforcement_result=result,
        )


        timeline.append(
            {
                "request":
                    request,

                "decision":
                    result.get(
                        "decision"
                    ),

                "executed":
                    result.get(
                        "executed"
                    ),

                "reason":
                    result.get(
                        "reason"
                    ),

                "blocked_capability":
                    result.get(
                        "blocked_capability"
                    ),

                "tool_result":
                    result.get(
                        "tool_result"
                    ),

                "attack_analysis":
                    result.get(
                        "attack_analysis"
                    ),

                "risk":
                    result.get(
                        "risk"
                    ),

                "containment_before":
                    result.get(
                        "containment_before"
                    ),

                "containment_after":
                    result.get(
                        "containment_after"
                    ),

                "explanation":
                    result.get(
                        "explanation"
                    ),

                "audit_event_id":
                    result.get(
                        "audit_event_id"
                    ),
            }
        )


        # -----------------------------------------------
        # Stop task if NEXUS intervenes
        # -----------------------------------------------

        if result.get(
            "decision"
        ) in {
            "BLOCK",
            "HOLD",
            "DENY",
        }:

            final_decision = (
                "SECURITY_INTERVENTION"
            )

            break


    # =====================================================
    # FINAL SECURITY STATE
    # =====================================================

    final_attack_analysis = (
        analyze_session(
            session_id
        )
    )


    final_risk = (
        evaluate_session_risk(
            session_id=session_id,

            allowed_services=verification[
                "allowed_services"
            ],

            allowed_resources=verification[
                "allowed_resources"
            ],
        )
    )


    final_containment = (
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
        )
    )


    executed_actions = [
        event
        for event in timeline
        if event["executed"]
        is True
    ]


    blocked_actions = [
        event
        for event in timeline
        if event["executed"]
        is False
    ]


    # =====================================================
    # FINAL RESPONSE
    # =====================================================

    return {
        "success": True,

        "task":
            task,

        "task_status":
            final_decision,

        "execution_backend":
            "SIMULATOR",

        "verification":
            verification,

        "plan":
            plan,

        "session":
            get_session(
                session_id
            ),

        "timeline":
            timeline,

        "summary": {
            "planned_actions":
                len(
                    plan["requests"]
                ),

            "executed_actions":
                len(
                    executed_actions
                ),

            "blocked_actions":
                len(
                    blocked_actions
                ),
        },

        "final_attack_analysis":
            final_attack_analysis,

        "final_risk":
            final_risk,

        "final_containment":
            final_containment,
    }