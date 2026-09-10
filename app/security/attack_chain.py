"""
NEXUS Attack-Chain Engine
=========================

Tracks ordered runtime behavior across an agent session.

NEXUS currently models two equivalent cloud-data
exfiltration paths:

AWS:
    IAM Discovery
        ↓
    Secrets Manager
        ↓
    Sensitive S3 Collection
        ↓
    External Exfiltration


Azure:
    Azure RBAC Discovery
        ↓
    Azure Key Vault
        ↓
    Sensitive Blob Collection
        ↓
    External Exfiltration


IMPORTANT:

The attack-chain engine only records actions that actually
executed and were observed by NEXUS.

Blocked actions are NOT falsely counted as completed stages.
"""

from app.security.session_state import (
    get_session,
)


# =========================================================
# ATTACK-CHAIN DEFINITIONS
# =========================================================

ATTACK_CHAINS = {

    # =====================================================
    # ORIGINAL AWS CHAIN
    #
    # Kept for:
    #   - existing tests
    #   - synthetic benchmark
    #   - backward compatibility
    # =====================================================

    "aws_cloud_data_exfiltration": {

        "name":
            "AWS Cloud Data Exfiltration",

        "provider":
            "AWS",

        "description": (
            "Agent progresses from AWS identity discovery "
            "to credential access, sensitive-data "
            "collection, and external exfiltration."
        ),

        "stages": [

            {
                "stage":
                    "DISCOVERY",

                "event":
                    "IAM:ListRoles",

                "capability":
                    "iam:ListRoles",

                "label":
                    "IAM Discovery",
            },

            {
                "stage":
                    "CREDENTIAL_ACCESS",

                "event":
                    "SecretsManager:GetSecretValue",

                "capability":
                    "secretsmanager:GetSecretValue",

                "label":
                    "Secrets Manager",
            },

            {
                "stage":
                    "COLLECTION",

                "event":
                    "S3:GetObject",

                "capability":
                    "s3:GetObject",

                "label":
                    "Sensitive S3",
            },

            {
                "stage":
                    "EXFILTRATION",

                "event":
                    "ExternalAPI:SendData",

                "capability":
                    "external:SendData",

                "label":
                    "External Transfer",
            },
        ],
    },


    # =====================================================
    # AZURE CHAIN
    # =====================================================

    "azure_cloud_data_exfiltration": {

        "name":
            "Azure Cloud Data Exfiltration",

        "provider":
            "AZURE",

        "description": (
            "Agent progresses from Azure RBAC discovery "
            "to Key Vault credential access, sensitive "
            "Blob collection, and external exfiltration."
        ),

        "stages": [

            {
                "stage":
                    "DISCOVERY",

                "event":
                    "AzureRBAC:ListRoleAssignments",

                "capability":
                    "azure.rbac:ListRoleAssignments",

                "label":
                    "Azure RBAC Discovery",
            },

            {
                "stage":
                    "CREDENTIAL_ACCESS",

                "event":
                    "AzureKeyVault:GetSecret",

                "capability":
                    "azure.keyvault:GetSecret",

                "label":
                    "Azure Key Vault",
            },

            {
                "stage":
                    "COLLECTION",

                "event":
                    "AzureBlobStorage:GetBlob",

                "capability":
                    "azure.blob:GetBlob",

                "label":
                    "Sensitive Blob Storage",
            },

            {
                "stage":
                    "EXFILTRATION",

                "event":
                    "ExternalAPI:SendData",

                "capability":
                    "external:SendData",

                "label":
                    "External Transfer",
            },
        ],
    },
}


# =========================================================
# ATTACK-CHAIN MATCHER
# =========================================================

def match_attack_chain(
    events: list[str],
    stages: list[dict],
):
    """
    Find how far an ordered runtime event sequence has
    progressed through an attack chain.

    Unrelated events are allowed between attack stages.

    Example:

        AzureStorage:GetProperties
        AzureMonitor:ReadMetrics
        AzureRBAC:ListRoleAssignments

    still correctly matches Azure RBAC DISCOVERY.

    Attack stages themselves must occur in order.
    """

    matched_stages = []

    stage_index = 0


    for event in events:

        # Entire attack chain already matched.
        if stage_index >= len(
            stages
        ):

            break


        expected_stage = (
            stages[
                stage_index
            ]
        )


        if (
            event
            == expected_stage[
                "event"
            ]
        ):

            matched_stages.append(
                {
                    "stage":
                        expected_stage[
                            "stage"
                        ],

                    "event":
                        expected_stage[
                            "event"
                        ],

                    "capability":
                        expected_stage.get(
                            "capability"
                        ),

                    "label":
                        expected_stage.get(
                            "label"
                        ),
                }
            )


            stage_index += 1


    return matched_stages


# =========================================================
# SEVERITY
# =========================================================

def calculate_severity(
    matched_count: int,
    total_stages: int,
):
    """
    Convert attack-chain progression into a simple
    runtime severity level.

    0 stages:
        NONE

    1 stage:
        LOW

    2 stages:
        MEDIUM

    3 stages:
        HIGH

    Complete chain:
        CRITICAL
    """

    if matched_count <= 0:

        return "NONE"


    if matched_count == 1:

        return "LOW"


    if matched_count == 2:

        return "MEDIUM"


    if (
        matched_count
        < total_stages
    ):

        return "HIGH"


    return "CRITICAL"


# =========================================================
# SINGLE CHAIN ANALYSIS
# =========================================================

def analyze_chain(
    chain_id: str,
    chain: dict,
    events: list[str],
):
    """
    Analyze one attack-chain definition against an
    ordered runtime event history.
    """

    stages = chain[
        "stages"
    ]


    matched_stages = (
        match_attack_chain(
            events,
            stages,
        )
    )


    matched_count = len(
        matched_stages
    )


    total_stages = len(
        stages
    )


    if total_stages == 0:

        completion_ratio = 0.0

    else:

        completion_ratio = (
            matched_count
            / total_stages
        )


    severity = (
        calculate_severity(
            matched_count,
            total_stages,
        )
    )


    complete = (
        matched_count
        == total_stages
    )


    # =====================================================
    # CURRENT STAGE
    # =====================================================

    current_stage = None


    if matched_stages:

        current_stage = (
            matched_stages[-1]
        )


    # =====================================================
    # NEXT EXPECTED STAGE
    # =====================================================

    next_expected_stage = None

    next_capability = None


    if not complete:

        next_expected_stage = (
            stages[
                matched_count
            ]
        )


        next_capability = (
            next_expected_stage.get(
                "capability"
            )
        )


    return {
        "chain_id":
            chain_id,

        "chain_name":
            chain[
                "name"
            ],

        "provider":
            chain.get(
                "provider",
                "UNKNOWN",
            ),

        "description":
            chain.get(
                "description"
            ),

        "matched_stages":
            matched_stages,

        "matched_count":
            matched_count,

        "total_stages":
            total_stages,

        "completion_ratio":
            round(
                completion_ratio,
                2,
            ),

        "severity":
            severity,

        "complete":
            complete,

        "current_stage":
            current_stage,

        "next_expected_stage":
            next_expected_stage,

        "next_capability":
            next_capability,
    }


# =========================================================
# MOST ADVANCED CHAIN
# =========================================================

def select_most_advanced_chain(
    analyses: list[dict],
):
    """
    Select the attack chain with the strongest observed
    progression.

    Primary sort:
        completion ratio

    Secondary sort:
        matched stage count

    This avoids arbitrary selection when multiple chains
    exist.
    """

    if not analyses:

        return None


    return max(
        analyses,

        key=lambda item: (
            item.get(
                "completion_ratio",
                0,
            ),

            item.get(
                "matched_count",
                0,
            ),
        ),
    )


# =========================================================
# SESSION ANALYSIS
# =========================================================

def analyze_session(
    session_id: str,
):
    """
    Analyze the complete ordered runtime history of one
    NEXUS agent session.

    Only successfully observed runtime actions appear here.
    """

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


    # =====================================================
    # EXTRACT ORDERED EVENTS
    # =====================================================

    actions = session.get(
        "actions",
        [],
    )


    events = []


    for action in actions:

        if not isinstance(
            action,
            dict,
        ):

            continue


        event = action.get(
            "event"
        )


        if isinstance(
            event,
            str,
        ) and event:

            events.append(
                event
            )


    # =====================================================
    # ANALYZE ALL KNOWN CHAINS
    # =====================================================

    analyses = []


    for (
        chain_id,
        chain,
    ) in ATTACK_CHAINS.items():

        analysis = (
            analyze_chain(
                chain_id=
                    chain_id,

                chain=
                    chain,

                events=
                    events,
            )
        )


        analyses.append(
            analysis
        )


    # =====================================================
    # MOST ADVANCED PATH
    # =====================================================

    most_advanced = (
        select_most_advanced_chain(
            analyses
        )
    )


    # =====================================================
    # NO CHAINS CONFIGURED
    # =====================================================

    if most_advanced is None:

        return {
            "success":
                True,

            "session_id":
                session_id,

            "events":
                events,

            "most_advanced_chain":
                None,

            "all_chain_analyses":
                [],
        }


    # =====================================================
    # RESPONSE
    # =====================================================

    return {
        "success":
            True,

        "session_id":
            session_id,

        "events":
            events,

        "most_advanced_chain":
            most_advanced,

        "all_chain_analyses":
            analyses,
    }