from app.tools.cloud_tools import (
    check_ec2,
    read_cloudwatch,
    read_application_logs,
    list_iam_roles,
    get_secret,
    read_s3,
    send_external,
)

from app.security.session_state import (
    get_session,
    set_session_status,
)

from app.security.observer import (
    observe_action,
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

from app.audit.logger import (
    log_security_event,
)

# =========================================================
# CONTROLLED RUNTIME DEVIATIONS
# =========================================================

# NEXUS may observe a low-risk discovery action even when
# it falls outside the approved troubleshooting task.
#
# This allows the Attack-Chain Engine to reconstruct
# suspicious progression without permitting dangerous
# credential/data actions.
#
# Dangerous out-of-scope actions are still blocked
# before execution.

MONITORED_DEVIATION_CAPABILITIES = {
    "iam:ListRoles",
}
# =========================================================
# AUDIT WRAPPER
# =========================================================

def finalize_enforcement_result(
    session_id: str,
    request: dict,
    result: dict,
):
    """
    Write the final NEXUS enforcement decision
    to the audit log before returning it.
    """

    audit_event = log_security_event(
        session_id=session_id,
        request=request,
        enforcement_result=result,
    )

    result["audit_event_id"] = (
        audit_event["event_id"]
    )

    return result


# =========================================================
# SIMULATED TOOL EXECUTION
# =========================================================

def execute_tool_request(
    request: dict,
):
    """
    Execute one simulated cloud tool.

    IMPORTANT:
    This function is only called AFTER NEXUS
    approves the request.
    """

    tool_name = request.get(
        "tool_name"
    )

    arguments = request.get(
        "arguments",
        {},
    )

    # -----------------------------------------------------
    # EC2
    # -----------------------------------------------------

    if tool_name == "check_ec2":

        return check_ec2(
            arguments["instance_id"]
        )

    # -----------------------------------------------------
    # CloudWatch Metrics
    # -----------------------------------------------------

    if tool_name == "read_cloudwatch":

        return read_cloudwatch(
            arguments["instance_id"]
        )

    # -----------------------------------------------------
    # CloudWatch Logs
    # -----------------------------------------------------

    if tool_name == "read_application_logs":

        return read_application_logs(
            arguments["instance_id"]
        )

    # -----------------------------------------------------
    # IAM
    # -----------------------------------------------------

    if tool_name == "list_iam_roles":

        return list_iam_roles()

    # -----------------------------------------------------
    # Secrets Manager
    # -----------------------------------------------------

    if tool_name == "get_secret":

        return get_secret(
            arguments["secret_name"]
        )

    # -----------------------------------------------------
    # S3
    # -----------------------------------------------------

    if tool_name == "read_s3":

        return read_s3(
            arguments["bucket"],
            arguments["object_name"],
        )

    # -----------------------------------------------------
    # External Destination
    # -----------------------------------------------------

    if tool_name == "send_external":

        return send_external(
            arguments["destination"]
        )

    # Unknown tool
    return None


# =========================================================
# PRE-ACTION ENFORCEMENT
# =========================================================

def enforce_action(
    session_id: str,
    request: dict,
    allowed_services: list[str],
    allowed_resources: list[str],
    identity_trusted: bool = True,
    task_trusted: bool = True,
):
    """
    Evaluate a requested cloud action BEFORE execution.

    Flow:

    1. Verify runtime session.
    2. Determine current containment state.
    3. Check requested capability.
    4. BLOCK / HOLD if necessary.
    5. Execute only if approved.
    6. Observe successful execution.
    7. Recalculate attack-chain progression.
    8. Recalculate risk.
    9. Recalculate containment.
    10. Write the final decision to the audit log.
    """

    # =====================================================
    # STEP 1 — CHECK SESSION
    # =====================================================

    session = get_session(
        session_id
    )

    if session is None:

        result = {
            "success": False,
            "decision": "DENY",
            "executed": False,
            "reason": (
                "Unknown runtime session."
            ),
            "request": request,
        }

        return finalize_enforcement_result(
            session_id,
            request,
            result,
        )

    # -----------------------------------------------------

    if session["status"] != "ACTIVE":

        result = {
            "success": False,
            "decision": "DENY",
            "executed": False,
            "reason": (
                "Runtime session is not active."
            ),
            "request": request,
        }

        return finalize_enforcement_result(
            session_id,
            request,
            result,
        )

    # =====================================================
    # STEP 2 — CURRENT CONTAINMENT STATE
    # =====================================================

    containment_before = plan_containment(
        session_id=session_id,

        allowed_services=
            allowed_services,

        allowed_resources=
            allowed_resources,

        identity_trusted=
            identity_trusted,

        task_trusted=
            task_trusted,
    )

    containment_mode = (
        containment_before.get(
            "containment_mode"
        )
    )

    # =====================================================
    # STEP 3 — FULL QUARANTINE
    # =====================================================

    if (
        containment_mode
        == "FULL_QUARANTINE"
    ):

        set_session_status(
            session_id,
            "QUARANTINED",
        )

        result = {
            "success": True,

            "decision":
                "BLOCK",

            "executed":
                False,

            "reason":
                "Agent session is fully quarantined.",

            "request":
                request,

            "containment_before":
                containment_before,
        }

        return finalize_enforcement_result(
            session_id,
            request,
            result,
        )

    # =====================================================
    # STEP 4 — REQUIRES REVIEW
    # =====================================================

    if (
        containment_mode
        == "REQUIRES_REVIEW"
    ):

        result = {
            "success": True,

            "decision":
                "HOLD",

            "executed":
                False,

            "reason": (
                "Requested action requires "
                "security review."
            ),

            "request":
                request,

            "containment_before":
                containment_before,
        }

        return finalize_enforcement_result(
            session_id,
            request,
            result,
        )

    # =====================================================
    # STEP 5 — MINIMUM CONTAINMENT
    # =====================================================

    if (
        containment_mode
        == "MINIMUM_CONTAINMENT"
    ):

        restricted = (
            containment_before.get(
                "restrict"
            )
        )

        if restricted is not None:

            restricted_capability = (
                restricted.get(
                    "capability"
                )
            )

            requested_capability = (
                request.get(
                    "capability"
                )
            )

            # ---------------------------------------------
            # REQUEST MATCHES ACTIVE CUT POINT
            # ---------------------------------------------

            if (
                requested_capability
                == restricted_capability
            ):

                result = {
                    "success":
                        True,

                    "decision":
                        "BLOCK",

                    "executed":
                        False,

                    "reason": (
                        "Requested capability matches "
                        "the active minimum containment "
                        "cut point."
                    ),

                    "blocked_capability":
                        requested_capability,

                    "request":
                        request,

                    "containment_before":
                        containment_before,
                }

                return finalize_enforcement_result(
                    session_id,
                    request,
                    result,
                )
    # =====================================================
    # PRE-ACTION TASK-SCOPE AUTHORIZATION
    # =====================================================

    requested_service = request.get(
        "service"
    )

    requested_resource = request.get(
        "resource"
    )

    requested_capability = request.get(
        "capability"
    )

    service_allowed = (
        requested_service
        in allowed_services
    )

    resource_allowed = (
        requested_resource
        in allowed_resources
    )

    inside_task_scope = (
        service_allowed
        and resource_allowed
    )

    # -----------------------------------------------------
    # Out-of-scope capability
    # -----------------------------------------------------

    if not inside_task_scope:

        # IAM ListRoles is deliberately permitted as a
        # monitored low-risk deviation in this prototype.
        #
        # Secrets, sensitive S3 access and external transfer
        # are NOT granted this exception.

        if (
            requested_capability
            not in
            MONITORED_DEVIATION_CAPABILITIES
        ):

            result = {
                "success": True,

                "decision": "BLOCK",

                "executed": False,

                "reason": (
                    "Requested capability falls "
                    "outside the verified task scope."
                ),

                "blocked_capability":
                    requested_capability,

                "request":
                    request,

                "containment_before":
                    containment_before,

                "scope_check": {
                    "service_allowed":
                        service_allowed,

                    "resource_allowed":
                        resource_allowed,

                    "approved_services":
                        allowed_services,

                    "approved_resources":
                        allowed_resources,
                },
            }

            return finalize_enforcement_result(
                session_id,
                request,
                result,
            )
    # =====================================================
    # STEP 6 — EXECUTE APPROVED TOOL
    # =====================================================

    tool_result = execute_tool_request(
        request
    )

    if tool_result is None:

        result = {
            "success":
                False,

            "decision":
                "DENY",

            "executed":
                False,

            "reason":
                "Unknown or unsupported tool.",

            "request":
                request,
        }

        return finalize_enforcement_result(
            session_id,
            request,
            result,
        )

    # =====================================================
    # STEP 7 — OBSERVE SUCCESSFUL EXECUTION
    # =====================================================

    observer_result = observe_action(
        session_id,
        tool_result,
    )

    # =====================================================
    # STEP 8 — ATTACK-CHAIN ANALYSIS
    # =====================================================

    attack_analysis = analyze_session(
        session_id
    )

    # =====================================================
    # STEP 9 — RISK ANALYSIS
    # =====================================================

    risk_analysis = evaluate_session_risk(
        session_id=session_id,

        allowed_services=
            allowed_services,

        allowed_resources=
            allowed_resources,
    )

    # =====================================================
    # STEP 10 — UPDATED CONTAINMENT
    # =====================================================

    containment_after = plan_containment(
        session_id=session_id,

        allowed_services=
            allowed_services,

        allowed_resources=
            allowed_resources,

        identity_trusted=
            identity_trusted,

        task_trusted=
            task_trusted,
    )

    # =====================================================
    # STEP 11 — FINAL ALLOW RESULT
    # =====================================================

    result = {
        "success":
            True,

        "decision":
            "ALLOW",

        "executed":
            True,

        "reason":
            "Requested capability passed NEXUS enforcement.",

        "request":
            request,

        "tool_result":
            tool_result,

        "observer":
            observer_result,

        "attack_analysis":
            attack_analysis[
                "most_advanced_chain"
            ],

        "risk":
            risk_analysis,

        "containment_before":
            containment_before,

        "containment_after":
            containment_after,
    }

    # =====================================================
    # STEP 12 — WRITE AUDIT LOG + RETURN
    # =====================================================

    return finalize_enforcement_result(
        session_id,
        request,
        result,
    )