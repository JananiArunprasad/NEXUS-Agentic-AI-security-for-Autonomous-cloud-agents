"""
NEXUS Trusted Tool Catalog
==========================

The LLM does NOT define cloud permissions.

It may only propose tool names from this trusted catalog.

Every proposed action is normalized into a canonical
NEXUS request before reaching the runtime Enforcer.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv


# =========================================================
# PROJECT CONFIG
# =========================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
    .parent
)

ENV_FILE = PROJECT_ROOT / ".env"

if ENV_FILE.exists():
    load_dotenv(
        dotenv_path=str(ENV_FILE)
    )


AZURE_STORAGE_ACCOUNT = os.getenv(
    "AZURE_STORAGE_ACCOUNT",
    "nexussec1028",
)


# =========================================================
# TRUSTED TOOL CATALOG
# =========================================================

TOOL_CATALOG = {

    # -----------------------------------------------------
    # REAL SAFE AZURE TOOLS
    # -----------------------------------------------------

    "inspect_azure_storage": {
        "description":
            "Inspect properties of the configured "
            "Azure Storage account.",

        "service":
            "AzureStorage",

        "action":
            "GetProperties",

        "capability":
            "azure.storage:GetProperties",

        "execution":
            "REAL",

        "risk":
            "LOW",
    },

    "read_azure_monitor": {
        "description":
            "Read Azure Monitor transaction metrics "
            "for the configured Storage account.",

        "service":
            "AzureMonitor",

        "action":
            "ReadMetrics",

        "capability":
            "azure.monitor:ReadMetrics",

        "execution":
            "REAL",

        "risk":
            "LOW",
    },


    # -----------------------------------------------------
    # SIMULATED AZURE ATTACK-CHAIN DISCOVERY
    # -----------------------------------------------------

    "list_azure_role_assignments": {
        "description":
            "Inspect Azure RBAC role assignments. "
            "Used only as a simulated discovery event.",

        "service":
            "AzureRBAC",

        "action":
            "ListRoleAssignments",

        "capability":
            "azure.rbac:ListRoleAssignments",

        "execution":
            "SIMULATION",

        "risk":
            "MEDIUM",
    },


    # -----------------------------------------------------
    # DANGEROUS ACTIONS
    #
    # These exist in the catalog so NEXUS can reason about
    # and BLOCK them.
    #
    # They have NO real Azure implementation.
    # -----------------------------------------------------

    "get_key_vault_secret": {
        "description":
            "Attempt to retrieve a credential or secret "
            "from Azure Key Vault.",

        "service":
            "AzureKeyVault",

        "action":
            "GetSecret",

        "capability":
            "azure.keyvault:GetSecret",

        "execution":
            "BLOCK_ONLY",

        "risk":
            "HIGH",
    },

    "read_sensitive_blob": {
        "description":
            "Attempt to read sensitive data from "
            "Azure Blob Storage.",

        "service":
            "AzureBlobStorage",

        "action":
            "GetBlob",

        "capability":
            "azure.blob:GetBlob",

        "execution":
            "BLOCK_ONLY",

        "risk":
            "HIGH",
    },

    "send_external": {
        "description":
            "Attempt to send collected information "
            "to an external destination.",

        "service":
            "ExternalAPI",

        "action":
            "SendData",

        "capability":
            "external:SendData",

        "execution":
            "BLOCK_ONLY",

        "risk":
            "CRITICAL",
    },
}


# =========================================================
# TOOL NAME HELPERS
# =========================================================

def get_supported_tool_names() -> List[str]:
    """
    Return trusted tool names the planner may propose.
    """

    return list(
        TOOL_CATALOG.keys()
    )


def is_supported_tool(
    tool_name: str,
) -> bool:
    """
    True only when the tool exists in the trusted catalog.
    """

    return (
        tool_name
        in TOOL_CATALOG
    )


def get_tool_definition(
    tool_name: str,
) -> Optional[Dict[str, Any]]:
    """
    Return metadata for one trusted tool.
    """

    return TOOL_CATALOG.get(
        tool_name
    )


# =========================================================
# DEFAULT ARGUMENTS
# =========================================================

def get_default_arguments(
    tool_name: str,
) -> Dict[str, Any]:
    """
    Generate trusted arguments for a supported tool.

    The LLM is not trusted to select arbitrary Azure
    account names or sensitive real resource identifiers.
    """

    if tool_name == "inspect_azure_storage":

        return {
            "storage_account":
                AZURE_STORAGE_ACCOUNT,
        }


    if tool_name == "read_azure_monitor":

        return {
            "storage_account":
                AZURE_STORAGE_ACCOUNT,
        }


    if tool_name == "list_azure_role_assignments":

        return {
            "resource":
                "azure-subscription",
        }


    if tool_name == "get_key_vault_secret":

        return {
            "secret":
                "production-db-password",
        }


    if tool_name == "read_sensitive_blob":

        return {
            "blob":
                "nexus-sensitive/"
                "customer_records.csv",
        }


    if tool_name == "send_external":

        return {
            "destination":
                "external-destination",
        }


    return {}


# =========================================================
# RESOURCE NORMALIZATION
# =========================================================

def get_resource(
    tool_name: str,
    arguments: Dict[str, Any],
) -> str:

    if tool_name in {
        "inspect_azure_storage",
        "read_azure_monitor",
    }:

        return arguments.get(
            "storage_account",
            AZURE_STORAGE_ACCOUNT,
        )


    if tool_name == "list_azure_role_assignments":

        return arguments.get(
            "resource",
            "azure-subscription",
        )


    if tool_name == "get_key_vault_secret":

        return arguments.get(
            "secret",
            "production-db-password",
        )


    if tool_name == "read_sensitive_blob":

        return arguments.get(
            "blob",
            "sensitive-blob",
        )


    if tool_name == "send_external":

        return arguments.get(
            "destination",
            "external-destination",
        )


    return "unknown"


# =========================================================
# CANONICAL REQUEST BUILDER
# =========================================================

def build_tool_request(
    tool_name: str,
) -> Optional[Dict[str, Any]]:
    """
    Convert a trusted tool name into the canonical
    request format understood by NEXUS.

    Unknown tools are rejected.
    """

    definition = get_tool_definition(
        tool_name
    )


    if definition is None:

        return None


    arguments = (
        get_default_arguments(
            tool_name
        )
    )


    resource = get_resource(
        tool_name,
        arguments,
    )


    return {
        "tool_name":
            tool_name,

        "service":
            definition[
                "service"
            ],

        "action":
            definition[
                "action"
            ],

        "capability":
            definition[
                "capability"
            ],

        "resource":
            resource,

        "arguments":
            arguments,

        "execution_type":
            definition[
                "execution"
            ],

        "catalog_risk":
            definition[
                "risk"
            ],
    }


# =========================================================
# NORMALIZE LLM TOOL CALL
# =========================================================

def normalize_tool_call(
    proposed_call: Any,
) -> Optional[Dict[str, Any]]:
    """
    Normalize a tool call proposed by the LLM.

    The LLM cannot control:
        - capability strings
        - Azure account binding
        - service/action metadata
        - real-vs-simulated classification

    It is only allowed to suggest the tool name.
    """

    if isinstance(
        proposed_call,
        str,
    ):

        tool_name = (
            proposed_call
            .strip()
        )


    elif isinstance(
        proposed_call,
        dict,
    ):

        tool_name = str(
            proposed_call.get(
                "tool_name",
                proposed_call.get(
                    "tool",
                    proposed_call.get(
                        "name",
                        "",
                    ),
                ),
            )
        ).strip()


    else:

        return None


    if not is_supported_tool(
        tool_name
    ):

        return None


    return (
        build_tool_request(
            tool_name
        )
    )


# =========================================================
# NORMALIZE COMPLETE PLAN
# =========================================================

def normalize_tool_plan(
    proposed_calls: List[Any],
) -> List[Dict[str, Any]]:
    """
    Normalize an entire AI-generated plan.

    Unknown or invented tools are silently discarded.
    """

    normalized = []


    for proposed_call in proposed_calls:

        request = (
            normalize_tool_call(
                proposed_call
            )
        )


        if request is not None:

            normalized.append(
                request
            )


    return normalized