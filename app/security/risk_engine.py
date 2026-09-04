from app.security.attack_chain import analyze_session
from app.security.session_state import get_session


# ---------------------------------------------------------
# Risk contributions
# ---------------------------------------------------------

ATTACK_CHAIN_POINTS = {
    "NONE": 0,
    "LOW": 10,
    "MEDIUM": 20,
    "HIGH": 35,
    "CRITICAL": 50,
}


# Resources we consider sensitive in our prototype.
SENSITIVE_RESOURCES = {
    "production-db-password": 15,
    "company-sensitive-data/customer_records.csv": 15,
}


# Actions specifically associated with credential access.
CREDENTIAL_ACTIONS = {
    ("SecretsManager", "GetSecretValue"): 10,
}


# External communication receives additional risk.
EXTERNAL_SERVICES = {
    "ExternalAPI": 20,
}


def get_risk_level(score: int):
    """
    Convert numerical risk score into a human-readable level.
    """

    if score == 0:
        return "NONE"

    if score < 25:
        return "LOW"

    if score < 50:
        return "MEDIUM"

    if score < 80:
        return "HIGH"

    return "CRITICAL"


def get_sensitive_resource_score(resource: str):
    """
    Check whether the current resource is considered sensitive.
    """

    return SENSITIVE_RESOURCES.get(
        resource,
        0,
    )


def evaluate_session_risk(
    session_id: str,
    allowed_services: list[str],
    allowed_resources: list[str],
):
    """
    Calculate the current NEXUS runtime risk score.

    The score combines:

    1. Attack-chain progression
    2. Task-scope violations
    3. Sensitive-resource access
    4. Credential access
    5. External communication
    """

    session = get_session(
        session_id
    )

    if session is None:

        return {
            "success": False,
            "error": "Unknown runtime session.",
        }

    # If no actions exist yet, there is no runtime risk.
    if not session["actions"]:

        return {
            "success": True,
            "score": 0,
            "risk_level": "NONE",
            "reasons": [],
        }

    # -----------------------------------------------------
    # Get latest action
    # -----------------------------------------------------

    latest_action = session["actions"][-1]

    service = latest_action["service"]
    action = latest_action["action"]
    resource = latest_action["resource"]

    score = 0
    reasons = []

    # =====================================================
    # SIGNAL 1 — ATTACK-CHAIN PROGRESSION
    # =====================================================

    attack_analysis = analyze_session(
        session_id
    )

    chain = attack_analysis[
        "most_advanced_chain"
    ]

    chain_severity = chain[
        "severity"
    ]

    chain_points = ATTACK_CHAIN_POINTS[
        chain_severity
    ]

    if chain_points > 0:

        score += chain_points

        reasons.append({
            "signal": "attack_chain_progression",
            "points": chain_points,
            "details": (
                f"{chain['matched_count']} of "
                f"{chain['total_stages']} attack stages matched."
            ),
        })

    # =====================================================
    # SIGNAL 2 — TASK-SCOPE VIOLATION
    # =====================================================

    service_allowed = (
        service in allowed_services
    )

    resource_allowed = (
        resource in allowed_resources
    )

    if not service_allowed or not resource_allowed:

        task_scope_points = 20

        score += task_scope_points

        reasons.append({
            "signal": "task_scope_violation",
            "points": task_scope_points,
            "details": (
                f"{service}:{action} on {resource} "
                "is outside the approved task scope."
            ),
        })

    # =====================================================
    # SIGNAL 3 — SENSITIVE RESOURCE
    # =====================================================

    sensitive_points = (
        get_sensitive_resource_score(
            resource
        )
    )

    if sensitive_points > 0:

        score += sensitive_points

        reasons.append({
            "signal": "sensitive_resource_access",
            "points": sensitive_points,
            "details": (
                f"Sensitive resource accessed: {resource}"
            ),
        })

    # =====================================================
    # SIGNAL 4 — CREDENTIAL ACCESS
    # =====================================================

    credential_points = (
        CREDENTIAL_ACTIONS.get(
            (service, action),
            0,
        )
    )

    if credential_points > 0:

        score += credential_points

        reasons.append({
            "signal": "credential_access",
            "points": credential_points,
            "details": (
                f"Credential-related action detected: "
                f"{service}:{action}"
            ),
        })

    # =====================================================
    # SIGNAL 5 — EXTERNAL COMMUNICATION
    # =====================================================

    external_points = (
        EXTERNAL_SERVICES.get(
            service,
            0,
        )
    )

    if external_points > 0:

        score += external_points

        reasons.append({
            "signal": "external_destination",
            "points": external_points,
            "details": (
                f"External communication detected: {resource}"
            ),
        })

    # -----------------------------------------------------
    # Keep score between 0 and 100
    # -----------------------------------------------------

    score = min(
        score,
        100,
    )

    risk_level = get_risk_level(
        score
    )

    return {
        "success": True,

        "session_id": session_id,

        "latest_event":
            latest_action["event"],

        "score": score,

        "risk_level": risk_level,

        "reasons": reasons,

        "attack_chain": {
            "chain_name":
                chain["chain_name"],

            "matched_count":
                chain["matched_count"],

            "total_stages":
                chain["total_stages"],

            "severity":
                chain["severity"],

            "complete":
                chain["complete"],
        },
    }