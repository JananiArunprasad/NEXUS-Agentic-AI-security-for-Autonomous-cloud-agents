from app.security.policy_rag import (
    retrieve_policies,
)


# =========================================================
# BUILD POLICY QUERY
# =========================================================

def build_policy_query(
    request: dict,
    enforcement_result: dict,
):
    """
    Convert the runtime decision into text that can
    be used to retrieve relevant security policies.
    """

    risk = enforcement_result.get(
        "risk",
        {},
    )

    containment = (
        enforcement_result.get(
            "containment_after"
        )
        or enforcement_result.get(
            "containment_before"
        )
        or {}
    )

    parts = [
        (
            f"Cloud service: "
            f"{request.get('service')}"
        ),

        (
            f"Requested action: "
            f"{request.get('action')}"
        ),

        (
            f"Capability: "
            f"{request.get('capability')}"
        ),

        (
            f"Resource: "
            f"{request.get('resource')}"
        ),

        (
            f"Security decision: "
            f"{enforcement_result.get('decision')}"
        ),

        (
            f"Executed: "
            f"{enforcement_result.get('executed')}"
        ),

        (
            f"Reason: "
            f"{enforcement_result.get('reason')}"
        ),

        (
            f"Risk level: "
            f"{risk.get('risk_level')}"
        ),

        (
            f"Containment mode: "
            f"{containment.get('containment_mode')}"
        ),
    ]

    return ". ".join(
        str(part)
        for part in parts
        if part
    )


# =========================================================
# BUILD HUMAN-READABLE REASONS
# =========================================================

def build_reasons(
    request: dict,
    enforcement_result: dict,
):
    """
    Produce deterministic explanation points from the
    actual NEXUS security decision.
    """

    reasons = []

    decision = enforcement_result.get(
        "decision"
    )

    capability = request.get(
        "capability"
    )

    service = request.get(
        "service"
    )

    resource = request.get(
        "resource"
    )

    reason = enforcement_result.get(
        "reason"
    )

    if reason:

        reasons.append(
            reason
        )

    if capability:

        reasons.append(
            (
                "Requested capability: "
                f"{capability}."
            )
        )

    if service:

        reasons.append(
            (
                "Requested cloud service: "
                f"{service}."
            )
        )

    if resource:

        reasons.append(
            (
                "Target resource: "
                f"{resource}."
            )
        )

    if decision == "BLOCK":

        blocked = (
            enforcement_result.get(
                "blocked_capability"
            )
        )

        if blocked:

            reasons.append(
                (
                    "NEXUS prevented execution of "
                    f"{blocked} before the tool "
                    "could run."
                )
            )

    if decision == "ALLOW":

        reasons.append(
            (
                "The requested action passed the "
                "current runtime enforcement checks."
            )
        )

    return reasons


# =========================================================
# MAIN EXPLANATION FUNCTION
# =========================================================

def explain_enforcement_decision(
    request: dict,
    enforcement_result: dict,
):
    """
    Explain a NEXUS enforcement decision using:

    1. Actual deterministic runtime evidence.
    2. Relevant retrieved policy knowledge.

    Policy retrieval supports explanation only.
    It does not modify the enforcement decision.
    """

    query = build_policy_query(
        request,
        enforcement_result,
    )

    policy_result = retrieve_policies(
        query=query,
        n_results=3,
    )

    decision = enforcement_result.get(
        "decision"
    )

    capability = request.get(
        "capability"
    )

    # -----------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------

    if decision == "BLOCK":

        summary = (
            "NEXUS blocked the requested "
            f"{capability} capability before "
            "execution because it matched the "
            "active runtime security restriction."
        )

    elif decision == "ALLOW":

        summary = (
            "NEXUS allowed the requested "
            f"{capability} capability because "
            "it did not violate the active "
            "runtime containment decision."
        )

    elif decision == "HOLD":

        summary = (
            "NEXUS held the requested action "
            "because additional security review "
            "is required."
        )

    else:

        summary = (
            "NEXUS denied the requested action "
            "because the runtime security "
            "requirements were not satisfied."
        )

    # -----------------------------------------------------
    # PRESERVED CAPABILITIES
    # -----------------------------------------------------

    containment = (
        enforcement_result.get(
            "containment_after"
        )
        or enforcement_result.get(
            "containment_before"
        )
        or {}
    )

    preserved = containment.get(
        "preserve",
        {},
    )

    # -----------------------------------------------------
    # FINAL EXPLANATION
    # -----------------------------------------------------

    return {
        "decision":
            decision,

        "summary":
            summary,

        "why":
            build_reasons(
                request,
                enforcement_result,
            ),

        "containment_mode":
            containment.get(
                "containment_mode"
            ),

        "preserved_scope":
            preserved,

        "policy_retrieval":
            {
                "success":
                    policy_result[
                        "success"
                    ],

                "results":
                    policy_result[
                        "results"
                    ],
            },

        "important_note": (
            "Retrieved policies support the "
            "explanation only. Enforcement is "
            "performed by deterministic NEXUS "
            "runtime security components."
        ),
    }