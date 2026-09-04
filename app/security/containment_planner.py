from app.security.attack_chain import analyze_session
from app.security.session_state import get_session


# =========================================================
# ATTACK-STAGE CAPABILITIES
# =========================================================

# These mappings describe the cloud capability associated
# with each attack-chain event.
#
# Later, when we integrate AWS, these can map to real
# IAM actions such as:
#
# secretsmanager:GetSecretValue
# s3:GetObject
# etc.

EVENT_CAPABILITIES = {

    "IAM:ListRoles": {
        "service": "IAM",
        "action": "ListRoles",
        "capability": "iam:ListRoles",
    },

    "SecretsManager:GetSecretValue": {
        "service": "SecretsManager",
        "action": "GetSecretValue",
        "capability": "secretsmanager:GetSecretValue",
    },

    "S3:GetObject": {
        "service": "S3",
        "action": "GetObject",
        "capability": "s3:GetObject",
    },

    "ExternalAPI:SendData": {
        "service": "ExternalAPI",
        "action": "SendData",
        "capability": "external:SendData",
    },
}


def build_preserved_scope(
    allowed_services: list[str],
    allowed_resources: list[str],
):
    """
    Describe the legitimate task capabilities that
    NEXUS should try to preserve.
    """

    return {
        "services": allowed_services,
        "resources": allowed_resources,
    }


def get_cut_point(chain: dict):
    """
    Determine the minimum attack-chain capability
    that should be restricted.

    For an incomplete linear attack chain, the next
    expected attack stage becomes the cut point.

    For a completed attack chain, the final stage is
    selected as the smallest end-to-end choke point.
    """

    # -----------------------------------------------------
    # Incomplete attack chain
    # -----------------------------------------------------

    if not chain["complete"]:

        next_stage = chain[
            "next_expected_stage"
        ]

        # No attack stage has been identified.
        if next_stage is None:
            return None

        event = next_stage["event"]

        capability = EVENT_CAPABILITIES.get(
            event
        )

        if capability is None:
            return None

        return {
            "stage": next_stage["stage"],
            "event": event,
            **capability,
        }

    # -----------------------------------------------------
    # Complete attack chain
    # -----------------------------------------------------

    matched_stages = chain[
        "matched_stages"
    ]

    if not matched_stages:
        return None

    final_stage = matched_stages[-1]

    event = final_stage["event"]

    capability = EVENT_CAPABILITIES.get(
        event
    )

    if capability is None:
        return None

    return {
        "stage": final_stage["stage"],
        "event": event,
        **capability,
    }


def plan_containment(
    session_id: str,
    allowed_services: list[str],
    allowed_resources: list[str],
    identity_trusted: bool = True,
    task_trusted: bool = True,
):
    """
    Determine the minimum containment action required
    for the current runtime session.

    Rules:

    1. If identity or task trust is lost:
       FULL QUARANTINE.

    2. If no attack-chain progression exists:
       no containment.

    3. If a verified agent is progressing through an
       attack chain:
       restrict the minimum attack-enabling capability
       while preserving approved task capabilities.
    """

    session = get_session(
        session_id
    )

    if session is None:

        return {
            "success": False,
            "error": "Unknown runtime session.",
        }

    preserved_scope = build_preserved_scope(
        allowed_services,
        allowed_resources,
    )

    # =====================================================
    # TRUST BOUNDARY
    # =====================================================

    if not identity_trusted or not task_trusted:

        return {
            "success": True,

            "session_id": session_id,

            "containment_mode":
                "FULL_QUARANTINE",

            "reason": (
                "Agent identity or approved-task trust "
                "cannot be established."
            ),

            "restrict": {
                "scope": "ALL_AGENT_CAPABILITIES",
            },

            "preserve": {
                "services": [],
                "resources": [],
            },
        }

    # =====================================================
    # ATTACK-CHAIN ANALYSIS
    # =====================================================

    analysis = analyze_session(
        session_id
    )

    if not analysis["success"]:

        return {
            "success": False,
            "error": (
                "Unable to analyze runtime session."
            ),
        }

    chain = analysis[
        "most_advanced_chain"
    ]

    # =====================================================
    # NO ATTACK PROGRESSION
    # =====================================================

    if chain["matched_count"] == 0:

        return {
            "success": True,

            "session_id": session_id,

            "containment_mode":
                "NONE",

            "reason": (
                "No known attack-chain progression "
                "has been detected."
            ),

            "restrict": None,

            "preserve":
                preserved_scope,

            "attack_chain": {
                "chain_name":
                    chain["chain_name"],

                "matched_count":
                    chain["matched_count"],

                "total_stages":
                    chain["total_stages"],

                "severity":
                    chain["severity"],
            },
        }

    # =====================================================
    # FIND MINIMUM CUT POINT
    # =====================================================

    cut_point = get_cut_point(
        chain
    )

    if cut_point is None:

        return {
            "success": True,

            "session_id": session_id,

            "containment_mode":
                "FULL_QUARANTINE",

            "reason": (
                "A safe minimum containment point "
                "could not be determined."
            ),

            "restrict": {
                "scope":
                    "ALL_AGENT_CAPABILITIES",
            },

            "preserve": {
                "services": [],
                "resources": [],
            },
        }

    # =====================================================
    # SAFETY CHECK
    # =====================================================

    # We do not want our "minimum containment" decision
    # to accidentally remove an approved service if a
    # safer alternative cannot be established.
    #
    # For this prototype, attack-stage capabilities are
    # expected to be outside the approved task scope.

    if cut_point["service"] in allowed_services:

        return {
            "success": True,

            "session_id": session_id,

            "containment_mode":
                "REQUIRES_REVIEW",

            "reason": (
                "The proposed attack-chain cut point "
                "overlaps with an approved task service."
            ),

            "restrict":
                cut_point,

            "preserve":
                preserved_scope,
        }

    # =====================================================
    # MINIMUM CONTAINMENT
    # =====================================================

    return {
        "success": True,

        "session_id": session_id,

        "containment_mode":
            "MINIMUM_CONTAINMENT",

        "reason": (
            "Restrict the next attack-enabling "
            "capability while preserving the "
            "approved task scope."
        ),

        "restrict":
            cut_point,

        "preserve":
            preserved_scope,

        "attack_chain": {
            "chain_name":
                chain["chain_name"],

            "matched_count":
                chain["matched_count"],

            "total_stages":
                chain["total_stages"],

            "completion_ratio":
                chain["completion_ratio"],

            "severity":
                chain["severity"],

            "complete":
                chain["complete"],
        },
    }