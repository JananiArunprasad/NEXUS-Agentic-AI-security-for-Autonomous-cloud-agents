"""
NEXUS Azure Runtime Executor
============================

This module is the execution boundary between the
NEXUS pre-action security Enforcer and Azure.

IMPORTANT SECURITY RULE:

    The AI planner NEVER calls Azure directly.

Flow:

    AI Planner
        ↓
    NEXUS Enforcer
        ↓
    ALLOW / BLOCK
        ↓
    Azure Runtime Executor
        ↓
    Real Azure API

Only low-risk, explicitly approved Azure operations
are implemented as real cloud calls.

Dangerous actions such as:

    - Key Vault secret retrieval
    - sensitive Blob retrieval
    - external data transfer

are deliberately NOT implemented against real Azure.
"""

from datetime import (
    datetime,
    timezone,
)

from typing import (
    Any,
    Dict,
    Optional,
)

from app.cloud.azure_backend import (
    execute_azure_approved_request,
)


# =========================================================
# EXECUTION MODES
# =========================================================

BACKEND_AZURE = "AZURE"

BACKEND_SIMULATION = "SIMULATION"


# =========================================================
# REAL AZURE TOOLS
# =========================================================

REAL_AZURE_TOOLS = {
    "inspect_azure_storage",
    "read_azure_monitor",
}


# =========================================================
# SIMULATED SECURITY-RESEARCH TOOLS
# =========================================================

SIMULATED_AZURE_TOOLS = {
    "list_azure_role_assignments",
}


# =========================================================
# DELIBERATELY UNIMPLEMENTED DANGEROUS TOOLS
# =========================================================

DANGEROUS_AZURE_TOOLS = {
    "get_key_vault_secret",
    "read_sensitive_blob",
    "send_external",
}


# =========================================================
# TIMESTAMP HELPER
# =========================================================

def utc_timestamp() -> str:
    """
    Return the current UTC timestamp.
    """

    return (
        datetime.now(
            timezone.utc
        )
        .isoformat()
    )


# =========================================================
# SIMULATED RBAC DISCOVERY
# =========================================================

def simulate_azure_rbac_discovery(
    request: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Simulate Azure RBAC discovery.

    This is intentionally simulated.

    NEXUS does NOT enumerate the user's real Azure role
    assignments during the attack-chain demonstration.

    The purpose is to provide a low-risk discovery event
    that the attack-chain engine can observe.
    """

    arguments = request.get(
        "arguments",
        {},
    )

    resource = arguments.get(
        "resource",
        "azure-subscription",
    )

    return {
        "service":
            "AzureRBAC",

        "action":
            "ListRoleAssignments",

        "resource":
            resource,

        "message":
            (
                "Simulated Azure RBAC "
                "role-assignment discovery."
            ),

        "timestamp":
            utc_timestamp(),

        "backend":
            BACKEND_SIMULATION,

        "executed":
            True,

        "simulated":
            True,

        "data": {
            "role_assignments": [
                {
                    "role":
                        "Reader",

                    "scope":
                        "NEXUS demo environment",
                }
            ]
        },
    }


# =========================================================
# REAL AZURE EXECUTION
# =========================================================

def execute_real_azure_tool(
    request: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """
    Execute a real Azure operation only if the tool is
    explicitly present in the real-cloud allowlist.
    """

    tool_name = request.get(
        "tool_name"
    )


    if tool_name not in REAL_AZURE_TOOLS:

        return None


    result = (
        execute_azure_approved_request(
            request
        )
    )


    if result is None:

        return None


    result["executed"] = True

    result["simulated"] = False

    result["backend"] = (
        BACKEND_AZURE
    )


    return result


# =========================================================
# MAIN EXECUTOR
# =========================================================

def execute_azure_runtime_request(
    request: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """
    Execute an action AFTER NEXUS has approved it.

    SECURITY DESIGN
    ---------------

    Real Azure:
        inspect_azure_storage
        read_azure_monitor

    Simulated:
        list_azure_role_assignments

    Never implemented:
        get_key_vault_secret
        read_sensitive_blob
        send_external

    Returning None means this executor refuses to
    execute the requested tool.
    """

    if not isinstance(
        request,
        dict,
    ):

        raise TypeError(
            "Azure runtime request "
            "must be a dictionary."
        )


    tool_name = request.get(
        "tool_name"
    )


    if not tool_name:

        raise ValueError(
            "Azure runtime request "
            "does not contain tool_name."
        )


    # =====================================================
    # REAL SAFE AZURE OPERATIONS
    # =====================================================

    if tool_name in REAL_AZURE_TOOLS:

        return (
            execute_real_azure_tool(
                request
            )
        )


    # =====================================================
    # SIMULATED DISCOVERY
    # =====================================================

    if (
        tool_name
        == "list_azure_role_assignments"
    ):

        return (
            simulate_azure_rbac_discovery(
                request
            )
        )


    # =====================================================
    # DANGEROUS OPERATIONS
    # =====================================================

    if tool_name in DANGEROUS_AZURE_TOOLS:

        return None


    # =====================================================
    # UNKNOWN TOOL
    # =====================================================

    return None


# =========================================================
# BACKEND INFORMATION
# =========================================================

def get_runtime_executor_info():
    """
    Return non-sensitive information about the current
    Azure runtime execution boundary.
    """

    return {
        "cloud":
            "Azure",

        "real_tools":
            sorted(
                REAL_AZURE_TOOLS
            ),

        "simulated_tools":
            sorted(
                SIMULATED_AZURE_TOOLS
            ),

        "dangerous_real_tools":
            [],

        "dangerous_tools_blocked":
            sorted(
                DANGEROUS_AZURE_TOOLS
            ),
    }