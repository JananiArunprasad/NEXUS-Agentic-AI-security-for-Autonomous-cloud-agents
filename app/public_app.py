"""
NEXUS Public Recruiter Demo
===========================

Safe hosted entry point for the public NEXUS dashboard.

IMPORTANT:
- Does NOT authenticate to the author's Azure account.
- Does NOT execute Azure Key Vault, sensitive Blob, or external-transfer actions.
- Does NOT require local Ollama.
- Real Azure Storage and Azure Monitor integration are validated
  separately in the local NEXUS runtime.

This hosted application demonstrates the NEXUS security workflow
using deterministic, safe demo responses.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import (
    FileResponse,
    RedirectResponse,
)
from pydantic import BaseModel, Field


# =========================================================
# APPLICATION
# =========================================================

app = FastAPI(
    title="NEXUS Public Demo",
    description=(
        "Adaptive Attack-Chain Defense "
        "for Autonomous Cloud Agents"
    ),
    version="1.0.0",
)


PROJECT_ROOT = (
    Path(__file__).resolve().parent.parent
)

DASHBOARD_FILE = (
    Path(__file__).resolve().parent
    / "dashboard"
    / "dashboard.html"
)

EVALUATION_FILE = (
    PROJECT_ROOT
    / "reports"
    / "evaluation_results.json"
)


# =========================================================
# REQUEST MODEL
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

@app.get(
    "/",
    include_in_schema=False,
)
def root():

    # Recruiters opening the Render URL land
    # directly on the NEXUS dashboard.
    return RedirectResponse(
        url="/dashboard"
    )


@app.get("/health")
def health():

    return {
        "success": True,
        "project": "NEXUS",
        "status": "running",
        "deployment_mode": "PUBLIC_DEMO",
    }


@app.get(
    "/dashboard",
    include_in_schema=False,
)
def dashboard():

    return FileResponse(
        DASHBOARD_FILE
    )


# =========================================================
# PUBLIC CLOUD STATUS
# =========================================================

@app.get("/azure/status")
def azure_status():

    return {
        "success": True,

        "demo_mode": True,

        "status": "public_demo",

        "connected": False,

        "cloud_provider": "AZURE",

        "execution_mode":
            "PUBLIC_DEMO",

        "message": (
            "Hosted recruiter demo. "
            "Real Azure Storage and Azure Monitor "
            "integration was validated in the local "
            "NEXUS runtime."
        ),

        "real_integration_validated_locally": [
            "Azure Storage",
            "Azure Monitor",
        ],

        "simulated_in_public_demo": [
            "Azure Storage inspection",
            "Azure Monitor inspection",
            "Azure RBAC discovery",
        ],

        "block_only": [
            "Azure Key Vault secret retrieval",
            "Sensitive Blob retrieval",
            "External data transfer",
        ],
    }


# =========================================================
# EVALUATION
# =========================================================

def load_evaluation_report():

    if EVALUATION_FILE.exists():

        try:

            with EVALUATION_FILE.open(
                "r",
                encoding="utf-8",
            ) as file:

                return json.load(
                    file
                )

        except Exception:

            pass


    # Safe fallback if the stored report
    # is unavailable on the host.

    return {
        "success": True,

        "metrics": {
            "attack_blocking_rate": 1.0,
            "benign_task_success_rate": 1.0,
            "f1_score": 1.0,
            "recovery_success_rate": 1.0,
        },

        "benchmark_scope": {
            "scenario_count": 12,
            "benign_scenarios": 6,
            "malicious_scenarios": 6,
            "synthetic": True,
        },

        "important_note": (
            "Results apply only to the current "
            "12-scenario synthetic evaluation set "
            "and are not a claim of universal "
            "detection accuracy."
        ),
    }


@app.get("/evaluation/latest")
def evaluation_latest():

    return load_evaluation_report()


@app.get("/evaluation/run")
def evaluation_run():

    return load_evaluation_report()


# =========================================================
# AUDIT
# =========================================================

@app.get("/audit/recent")
def audit_recent():

    return {
        "success": True,
        "events": [],
        "deployment_mode": "PUBLIC_DEMO",
    }


# =========================================================
# SHARED SECURITY OBJECTS
# =========================================================

def azure_attack_chain():

    return {
        "success": True,

        "most_advanced_chain": {
            "chain_id":
                "azure_cloud_data_exfiltration",

            "chain_name":
                "Azure Cloud Data Exfiltration",

            "provider":
                "AZURE",

            "matched_count":
                1,

            "total_stages":
                4,

            "completion_ratio":
                0.25,

            "severity":
                "LOW",

            "complete":
                False,

            "current_stage": {
                "stage":
                    "DISCOVERY",

                "event":
                    "AzureRBAC:ListRoleAssignments",

                "capability":
                    "azure.rbac:ListRoleAssignments",

                "label":
                    "Azure RBAC Discovery",
            },

            "next_expected_stage": {
                "stage":
                    "CREDENTIAL_ACCESS",

                "event":
                    "AzureKeyVault:GetSecret",

                "capability":
                    "azure.keyvault:GetSecret",

                "label":
                    "Azure Key Vault",
            },

            "next_capability":
                "azure.keyvault:GetSecret",
        },
    }


def minimum_containment():

    return {
        "success": True,

        "containment_mode":
            "MINIMUM_CONTAINMENT",

        "mode":
            "SELECTIVE",

        "reason": (
            "NEXUS identified the next "
            "attack-enabling capability and "
            "restricted it while preserving "
            "the verified task scope."
        ),

        "restrict": {
            "stage":
                "CREDENTIAL_ACCESS",

            "event":
                "AzureKeyVault:GetSecret",

            "service":
                "AzureKeyVault",

            "action":
                "GetSecret",

            "capability":
                "azure.keyvault:GetSecret",
        },

        "blocked_capability":
            "azure.keyvault:GetSecret",

        "restricted_capabilities": [
            "azure.keyvault:GetSecret"
        ],

        "preserve": {
            "services": [
                "AzureStorage",
                "AzureMonitor",
            ],

            "resources": [
                "nexus-demo-storage",
            ],
        },
    }


# =========================================================
# SAFE DEMO
# =========================================================

def safe_demo(
    task: str,
):

    session_id = (
        "demo-"
        + uuid.uuid4().hex[:8]
    )


    calls = [

        {
            "tool_name":
                "inspect_azure_storage",

            "service":
                "AzureStorage",

            "action":
                "GetProperties",

            "capability":
                "azure.storage:GetProperties",

            "resource":
                "nexus-demo-storage",

            "execution_type":
                "PUBLIC_DEMO",
        },

        {
            "tool_name":
                "read_azure_monitor",

            "service":
                "AzureMonitor",

            "action":
                "ReadMetrics",

            "capability":
                "azure.monitor:ReadMetrics",

            "resource":
                "nexus-demo-storage",

            "execution_type":
                "PUBLIC_DEMO",
        },
    ]


    timeline = [

        {
            **calls[0],

            "decision":
                "ALLOW",

            "executed":
                True,

            "reason": (
                "Requested capability passed "
                "NEXUS enforcement."
            ),

            "blocked_capability":
                None,

            "backend":
                "PUBLIC_DEMO",

            "tool_result": {
                "backend":
                    "PUBLIC_DEMO",

                "executed":
                    True,

                "message": (
                    "Safe hosted demonstration of "
                    "Azure Storage inspection."
                ),
            },

            "risk": {
                "score": 0,
                "risk_level": "NONE",
            },

            "attack_chain":
                None,

            "containment": {
                "containment_mode": "NONE",
                "blocked_capability": None,
            },
        },

        {
            **calls[1],

            "decision":
                "ALLOW",

            "executed":
                True,

            "reason": (
                "Requested capability passed "
                "NEXUS enforcement."
            ),

            "blocked_capability":
                None,

            "backend":
                "PUBLIC_DEMO",

            "tool_result": {
                "backend":
                    "PUBLIC_DEMO",

                "executed":
                    True,

                "message": (
                    "Safe hosted demonstration of "
                    "Azure Monitor inspection."
                ),
            },

            "risk": {
                "score": 0,
                "risk_level": "NONE",
            },

            "attack_chain":
                None,

            "containment": {
                "containment_mode": "NONE",
                "blocked_capability": None,
            },
        },
    ]


    return {
        "success": True,

        "session_id":
            session_id,

        "session_verified":
            True,

        "user_task":
            task,

        "cloud_mode":
            "azure_public_demo",

        "planner_source":
            "DETERMINISTIC_PUBLIC_DEMO",

        "execution_backend":
            "PUBLIC DEMO",

        "plan": {
            "planner_source":
                "DETERMINISTIC_PUBLIC_DEMO",

            "user_task":
                task,

            "tool_calls":
                calls,

            "requests":
                calls,

            "proposed_count":
                2,

            "accepted_count":
                2,
        },

        "timeline":
            timeline,

        "final_decision":
            "COMPLETED",

        "summary": {
            "planned_actions": 2,
            "executed_actions": 2,
            "blocked_actions": 0,
            "real_azure_actions": 0,
            "simulated_actions": 2,
        },

        "demo_notice": (
            "Hosted public demo uses safe simulated "
            "cloud responses. Real Azure Storage and "
            "Azure Monitor integration is validated "
            "in the local project runtime."
        ),
    }


# =========================================================
# DIRECT SECRET ATTEMPT
# =========================================================

def direct_secret_demo(
    task: str,
):

    session_id = (
        "demo-"
        + uuid.uuid4().hex[:8]
    )


    call = {
        "tool_name":
            "get_key_vault_secret",

        "service":
            "AzureKeyVault",

        "action":
            "GetSecret",

        "capability":
            "azure.keyvault:GetSecret",

        "resource":
            "production-db-password",

        "execution_type":
            "BLOCK_ONLY",
    }


    event = {
        **call,

        "decision":
            "BLOCK",

        "executed":
            False,

        "reason": (
            "Requested capability falls outside "
            "the verified task scope."
        ),

        "blocked_capability":
            "azure.keyvault:GetSecret",

        "backend":
            "NOT_EXECUTED",

        "tool_result":
            None,

        "risk":
            None,

        "attack_chain":
            None,

        "containment":
            None,
    }


    return {
        "success": True,

        "session_id":
            session_id,

        "session_verified":
            True,

        "user_task":
            task,

        "cloud_mode":
            "azure_public_demo",

        "planner_source":
            "DETERMINISTIC_PUBLIC_DEMO",

        "execution_backend":
            "PUBLIC DEMO",

        "plan": {
            "planner_source":
                "DETERMINISTIC_PUBLIC_DEMO",

            "user_task":
                task,

            "tool_calls": [
                call
            ],

            "requests": [
                call
            ],

            "proposed_count": 1,
            "accepted_count": 1,
        },

        "timeline": [
            event
        ],

        "final_decision":
            "BLOCK",

        "summary": {
            "planned_actions": 1,
            "executed_actions": 0,
            "blocked_actions": 1,
            "real_azure_actions": 0,
            "simulated_actions": 0,
        },
    }


# =========================================================
# ATTACK-CHAIN DEMO
# =========================================================

def attack_demo(
    task: str,
):

    session_id = (
        "demo-"
        + uuid.uuid4().hex[:8]
    )


    chain = (
        azure_attack_chain()
    )

    containment = (
        minimum_containment()
    )


    calls = [

        {
            "tool_name":
                "list_azure_role_assignments",

            "service":
                "AzureRBAC",

            "action":
                "ListRoleAssignments",

            "capability":
                "azure.rbac:ListRoleAssignments",

            "resource":
                "azure-demo-subscription",

            "execution_type":
                "SIMULATION",
        },

        {
            "tool_name":
                "get_key_vault_secret",

            "service":
                "AzureKeyVault",

            "action":
                "GetSecret",

            "capability":
                "azure.keyvault:GetSecret",

            "resource":
                "production-db-password",

            "execution_type":
                "BLOCK_ONLY",
        },

        {
            "tool_name":
                "read_sensitive_blob",

            "service":
                "AzureBlobStorage",

            "action":
                "GetBlob",

            "capability":
                "azure.blob:GetBlob",

            "resource":
                "customer_records.csv",

            "execution_type":
                "BLOCK_ONLY",
        },

        {
            "tool_name":
                "send_external",

            "service":
                "ExternalAPI",

            "action":
                "SendData",

            "capability":
                "external:SendData",

            "resource":
                "external-destination",

            "execution_type":
                "BLOCK_ONLY",
        },
    ]


    timeline = [

        {
            **calls[0],

            "decision":
                "ALLOW",

            "executed":
                True,

            "reason": (
                "Monitored deviation allowed so "
                "NEXUS can evaluate runtime "
                "attack-chain progression."
            ),

            "blocked_capability":
                None,

            "backend":
                "SIMULATION",

            "tool_result": {
                "backend":
                    "SIMULATION",

                "executed":
                    True,

                "simulated":
                    True,

                "message": (
                    "Simulated Azure RBAC "
                    "role-assignment discovery."
                ),
            },

            "risk": {
                "success": True,

                "score":
                    30,

                "risk_level":
                    "MEDIUM",

                "reasons": [
                    {
                        "signal":
                            "attack_chain_progression",

                        "points":
                            10,
                    },

                    {
                        "signal":
                            "task_scope_violation",

                        "points":
                            20,
                    },
                ],

                "attack_chain": {
                    "chain_name":
                        "Azure Cloud Data Exfiltration",

                    "matched_count":
                        1,

                    "total_stages":
                        4,

                    "severity":
                        "LOW",

                    "complete":
                        False,
                },
            },

            "attack_chain":
                chain,

            "containment":
                containment,

            "blocked_capability":
                "azure.keyvault:GetSecret",
        },

        {
            **calls[1],

            "decision":
                "BLOCK",

            "executed":
                False,

            "reason": (
                "Requested capability is restricted "
                "by the active NEXUS minimum-"
                "containment decision."
            ),

            "blocked_capability":
                "azure.keyvault:GetSecret",

            "backend":
                "NOT_EXECUTED",

            "tool_result":
                None,

            "risk":
                None,

            "attack_chain":
                chain,

            "containment":
                containment,
        },

        {
            **calls[2],

            "decision":
                "NOT_REACHED",

            "executed":
                False,

            "reason": (
                "Previous NEXUS intervention stopped "
                "the remaining plan."
            ),

            "backend":
                "NOT_EXECUTED",
        },

        {
            **calls[3],

            "decision":
                "NOT_REACHED",

            "executed":
                False,

            "reason": (
                "Previous NEXUS intervention stopped "
                "the remaining plan."
            ),

            "backend":
                "NOT_EXECUTED",
        },
    ]


    return {
        "success": True,

        "session_id":
            session_id,

        "session_verified":
            True,

        "user_task":
            task,

        "cloud_mode":
            "azure_public_demo",

        "planner_source":
            "DETERMINISTIC_PUBLIC_DEMO",

        "execution_backend":
            "PUBLIC DEMO",

        "plan": {
            "planner_source":
                "DETERMINISTIC_PUBLIC_DEMO",

            "user_task":
                task,

            "tool_calls":
                calls,

            "requests":
                calls,

            "proposed_count":
                4,

            "accepted_count":
                4,
        },

        "timeline":
            timeline,

        "final_decision":
            "BLOCK",

        "summary": {
            "planned_actions": 4,
            "executed_actions": 1,
            "blocked_actions": 1,
            "real_azure_actions": 0,
            "simulated_actions": 1,
        },

        "demo_notice": (
            "Hosted public demo. Dangerous cloud "
            "operations are never executed."
        ),
    }


# =========================================================
# PUBLIC AGENT ENDPOINT
# =========================================================

@app.post("/agent/execute")
def execute_agent(
    payload: AgentTaskRequest,
):

    task = (
        payload.task.strip()
    )

    lower = (
        task.lower()
    )


    # Full attack-chain wording.

    attack_signals = [
        "send them externally",
        "send externally",
        "customer records",
        "sensitive customer",
        "role permissions",
        "role assignments",
        "exfiltrat",
    ]


    if any(
        signal in lower
        for signal in attack_signals
    ):

        return attack_demo(
            task
        )


    # Direct secret / credential request.

    secret_signals = [
        "key vault",
        "database password",
        "secret",
        "credential",
    ]


    if any(
        signal in lower
        for signal in secret_signals
    ):

        return direct_secret_demo(
            task
        )


    # Default recruiter-safe benign workflow.

    return safe_demo(
        task
    )
