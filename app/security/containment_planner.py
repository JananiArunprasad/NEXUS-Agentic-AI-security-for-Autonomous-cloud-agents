"""
NEXUS Minimum Containment Planner
=================================

Purpose:
    Identify the smallest capability that can be restricted
    to break an observed attack path while preserving the
    approved task scope.

Supported modeled attack paths:

AWS:
    IAM
      ↓
    Secrets Manager
      ↓
    S3
      ↓
    External Transfer

Azure:
    Azure RBAC
      ↓
    Azure Key Vault
      ↓
    Azure Blob Storage
      ↓
    External Transfer


CORE SAFETY PRINCIPLE:

Trusted agent:
    Minimum / selective containment.

Untrusted agent:
    Full quarantine.
"""

from app.security.attack_chain import (
    analyze_session,
)

from app.security.session_state import (
    get_session,
)


# =========================================================
# ATTACK-STAGE CAPABILITY MAP
# =========================================================

EVENT_CAPABILITIES = {

    # =====================================================
    # AWS
    # =====================================================

    "IAM:ListRoles": {
        "service":
            "IAM",

        "action":
            "ListRoles",

        "capability":
            "iam:ListRoles",
    },


    "SecretsManager:GetSecretValue": {
        "service":
            "SecretsManager",

        "action":
            "GetSecretValue",

        "capability":
            "secretsmanager:GetSecretValue",
    },


    "S3:GetObject": {
        "service":
            "S3",

        "action":
            "GetObject",

        "capability":
            "s3:GetObject",
    },


    # =====================================================
    # AZURE
    # =====================================================

    "AzureRBAC:ListRoleAssignments": {
        "service":
            "AzureRBAC",

        "action":
            "ListRoleAssignments",

        "capability":
            "azure.rbac:ListRoleAssignments",
    },


    "AzureKeyVault:GetSecret": {
        "service":
            "AzureKeyVault",

        "action":
            "GetSecret",

        "capability":
            "azure.keyvault:GetSecret",
    },


    "AzureBlobStorage:GetBlob": {
        "service":
            "AzureBlobStorage",

        "action":
            "GetBlob",

        "capability":
            "azure.blob:GetBlob",
    },

    "AzureRBAC:ListRoleAssignments": {
        "service": "AzureRBAC",
        "action": "ListRoleAssignments",
        "capability": "azure.rbac:ListRoleAssignments",
    },

    "AzureKeyVault:GetSecret": {
        "service": "AzureKeyVault",
        "action": "GetSecret",
        "capability": "azure.keyvault:GetSecret",
    },

    "AzureBlobStorage:GetBlob": {
        "service": "AzureBlobStorage",
        "action": "GetBlob",
        "capability": "azure.blob:GetBlob",
    },
    # =====================================================
    # PROVIDER-INDEPENDENT EXFILTRATION
    # =====================================================

    "ExternalAPI:SendData": {
        "service":
            "ExternalAPI",

        "action":
            "SendData",

        "capability":
            "external:SendData",
    },
}


# =========================================================
# PRESERVED TASK SCOPE
# =========================================================

def build_preserved_scope(
    allowed_services: list[str],
    allowed_resources: list[str],
):
    """
    Describe the verified task capabilities that NEXUS
    should preserve when selective containment is safe.
    """

    return {
        "services":
            list(
                allowed_services
            ),

        "resources":
            list(
                allowed_resources
            ),
    }


# =========================================================
# CUT-POINT LOOKUP
# =========================================================

def get_event_capability(
    event: str,
):
    """
    Convert an attack-chain event into a cloud capability.
    """

    capability = (
        EVENT_CAPABILITIES.get(
            event
        )
    )


    if capability is None:

        return None


    return dict(
        capability
    )


# =========================================================
# MINIMUM ATTACK-CHAIN CUT POINT
# =========================================================

def get_cut_point(
    chain: dict,
):
    """
    Determine the minimum capability that should be
    restricted to stop continued attack progression.

    Incomplete chain:
        Restrict the NEXT expected stage.

    Completed chain:
        Restrict the final attack-enabling stage.

    Example:

        Azure RBAC observed
                ↓
        next stage = Key Vault
                ↓
        cut point =
        azure.keyvault:GetSecret
    """

    if not isinstance(
        chain,
        dict,
    ):

        return None


    # =====================================================
    # INCOMPLETE CHAIN
    # =====================================================

    if not chain.get(
        "complete",
        False,
    ):

        next_stage = (
            chain.get(
                "next_expected_stage"
            )
        )


        if not next_stage:

            return None


        event = (
            next_stage.get(
                "event"
            )
        )


        if not event:

            return None


        capability = (
            get_event_capability(
                event
            )
        )


        if capability is None:

            return None


        return {
            "stage":
                next_stage.get(
                    "stage"
                ),

            "event":
                event,

            "label":
                next_stage.get(
                    "label"
                ),

            **capability,
        }


    # =====================================================
    # COMPLETED CHAIN
    # =====================================================

    matched_stages = (
        chain.get(
            "matched_stages",
            [],
        )
    )


    if not matched_stages:

        return None


    final_stage = (
        matched_stages[-1]
    )


    event = (
        final_stage.get(
            "event"
        )
    )


    if not event:

        return None


    capability = (
        get_event_capability(
            event
        )
    )


    if capability is None:

        return None


    return {
        "stage":
            final_stage.get(
                "stage"
            ),

        "event":
            event,

        "label":
            final_stage.get(
                "label"
            ),

        **capability,
    }


# =========================================================
# FULL QUARANTINE RESPONSE
# =========================================================

def build_full_quarantine(
    session_id: str,
    reason: str,
    attack_chain: dict | None = None,
):
    """
    Build a consistent full-quarantine response.
    """

    result = {
        "success":
            True,

        "session_id":
            session_id,

        # Existing NEXUS field
        "containment_mode":
            "FULL_QUARANTINE",

        # Compatibility with Enforcer
        "mode":
            "FULL_QUARANTINE",

        "reason":
            reason,

        "restrict": {
            "scope":
                "ALL_AGENT_CAPABILITIES",
        },

        "blocked_capability":
            None,

        "restricted_capabilities":
            [],

        "preserve": {
            "services":
                [],

            "resources":
                [],
        },
    }


    if attack_chain is not None:

        result[
            "attack_chain"
        ] = attack_chain


    return result


# =========================================================
# MAIN CONTAINMENT PLANNER
# =========================================================

def plan_containment(
    session_id: str,
    allowed_services: list[str],
    allowed_resources: list[str],
    identity_trusted: bool = True,
    task_trusted: bool = True,
):
    """
    Determine the minimum runtime containment action.

    RULES
    -----

    1. Unknown runtime session:
       return error.

    2. Identity/task trust lost:
       FULL_QUARANTINE.

    3. No attack-chain progression:
       NONE.

    4. Trusted agent progressing through an attack chain:
       identify the next attack-enabling capability.

    5. If the proposed cut point overlaps with the
       approved workload:
       REQUIRES_REVIEW.

    6. Otherwise:
       MINIMUM_CONTAINMENT.
    """

    # =====================================================
    # SESSION
    # =====================================================

    session = (
        get_session(
            session_id
        )
    )


    if session is None:

        return {
            "success":
                False,

            "error":
                "Unknown runtime session.",
        }


    preserved_scope = (
        build_preserved_scope(
            allowed_services,
            allowed_resources,
        )
    )


    # =====================================================
    # TRUST BOUNDARY
    # =====================================================

    if (
        not identity_trusted
        or not task_trusted
    ):

        return (
            build_full_quarantine(
                session_id=
                    session_id,

                reason=(
                    "Agent identity or approved-task "
                    "trust cannot be established."
                ),
            )
        )


    # =====================================================
    # ATTACK-CHAIN ANALYSIS
    # =====================================================

    analysis = (
        analyze_session(
            session_id
        )
    )


    if not analysis.get(
        "success"
    ):

        return {
            "success":
                False,

            "error":
                (
                    "Unable to analyze "
                    "runtime session."
                ),
        }


    chain = (
        analysis.get(
            "most_advanced_chain"
        )
    )


    if chain is None:

        return {
            "success":
                True,

            "session_id":
                session_id,

            "containment_mode":
                "NONE",

            "mode":
                "NONE",

            "reason":
                (
                    "No attack-chain "
                    "definition is available."
                ),

            "restrict":
                None,

            "blocked_capability":
                None,

            "restricted_capabilities":
                [],

            "preserve":
                preserved_scope,

            "attack_chain":
                None,
        }


    # =====================================================
    # ATTACK-CHAIN SUMMARY
    # =====================================================

    attack_chain_summary = {
        "chain_id":
            chain.get(
                "chain_id"
            ),

        "chain_name":
            chain.get(
                "chain_name"
            ),

        "provider":
            chain.get(
                "provider"
            ),

        "matched_count":
            chain.get(
                "matched_count",
                0,
            ),

        "total_stages":
            chain.get(
                "total_stages",
                0,
            ),

        "completion_ratio":
            chain.get(
                "completion_ratio",
                0,
            ),

        "severity":
            chain.get(
                "severity",
                "NONE",
            ),

        "complete":
            chain.get(
                "complete",
                False,
            ),

        "current_stage":
            chain.get(
                "current_stage"
            ),

        "next_expected_stage":
            chain.get(
                "next_expected_stage"
            ),

        "next_capability":
            chain.get(
                "next_capability"
            ),
    }


    # =====================================================
    # NO ATTACK PROGRESSION
    # =====================================================

    if (
        chain.get(
            "matched_count",
            0,
        )
        == 0
    ):

        return {
            "success":
                True,

            "session_id":
                session_id,

            "containment_mode":
                "NONE",

            "mode":
                "NONE",

            "reason":
                (
                    "No known attack-chain "
                    "progression has been detected."
                ),

            "restrict":
                None,

            "blocked_capability":
                None,

            "restricted_capabilities":
                [],

            "preserve":
                preserved_scope,

            "attack_chain":
                attack_chain_summary,
        }


    # =====================================================
    # FIND MINIMUM CUT POINT
    # =====================================================

    cut_point = (
        get_cut_point(
            chain
        )
    )


    # -----------------------------------------------------
    # Unknown / unsupported cut point
    # -----------------------------------------------------

    if cut_point is None:

        return (
            build_full_quarantine(
                session_id=
                    session_id,

                reason=(
                    "Attack progression was detected, "
                    "but a safe minimum containment "
                    "point could not be determined."
                ),

                attack_chain=
                    attack_chain_summary,
            )
        )


    blocked_capability = (
        cut_point.get(
            "capability"
        )
    )


    # =====================================================
    # SAFETY CHECK:
    # CUT POINT OVERLAPS APPROVED WORKLOAD
    # =====================================================

    if (
        cut_point.get(
            "service"
        )
        in allowed_services
    ):

        return {
            "success":
                True,

            "session_id":
                session_id,

            "containment_mode":
                "REQUIRES_REVIEW",

            "mode":
                "REQUIRES_REVIEW",

            "reason":
                (
                    "The minimum attack-chain "
                    "cut point overlaps with an "
                    "approved task service."
                ),

            "restrict":
                cut_point,

            "blocked_capability":
                blocked_capability,

            "restricted_capabilities": (
                [blocked_capability]
                if blocked_capability
                else []
            ),

            "preserve":
                preserved_scope,

            "attack_chain":
                attack_chain_summary,
        }


    # =====================================================
    # MINIMUM / SELECTIVE CONTAINMENT
    # =====================================================

    return {
        "success":
            True,

        "session_id":
            session_id,

        # Keep original project terminology
        "containment_mode":
            "MINIMUM_CONTAINMENT",

        # Useful compatibility / UI label
        "mode":
            "SELECTIVE",

        "reason":
            (
                "NEXUS identified the next "
                "attack-enabling capability and "
                "restricted it while preserving "
                "the verified task scope."
            ),

        "restrict":
            cut_point,

        # These top-level fields are intentional.
        # The Enforcer can consume them directly.
        "blocked_capability":
            blocked_capability,

        "restricted_capabilities": (
            [blocked_capability]
            if blocked_capability
            else []
        ),

        "preserve":
            preserved_scope,

        "attack_chain":
            attack_chain_summary,
    }