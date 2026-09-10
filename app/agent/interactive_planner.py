"""
NEXUS Interactive Planner
=========================

Natural-language user task
        ↓
Local Mistral
        ↓
Proposed tool names
        ↓
Trusted Tool Catalog
        ↓
Canonical NEXUS requests

SECURITY RULE:

The LLM proposes intent.

The trusted catalog defines the real capabilities.
"""

import json
import os
import urllib.error
import urllib.request

from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv

from app.agent.tool_catalog import (
    get_supported_tool_names,
    normalize_tool_plan,
)


# =========================================================
# CONFIGURATION
# =========================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
    .parent
)

ENV_FILE = (
    PROJECT_ROOT
    / ".env"
)

if ENV_FILE.exists():

    load_dotenv(
        dotenv_path=str(
            ENV_FILE
        )
    )


OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://127.0.0.1:11434",
).rstrip("/")


OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "mistral:7b-instruct",
)


# =========================================================
# SYSTEM PROMPT
# =========================================================

def build_system_prompt() -> str:

    supported_tools = (
        get_supported_tool_names()
    )


    return f"""
You are the planning component of NEXUS,
a defensive cloud-agent security research prototype.

You DO NOT execute cloud operations.
You DO NOT make authorization decisions.
You ONLY propose a sequence of tool names.

The trusted tools available are:

{json.dumps(supported_tools, indent=2)}

Tool meanings:

inspect_azure_storage
- Inspect the configured Azure Storage account.
- Normal legitimate cloud administration.

read_azure_monitor
- Read recent Azure Monitor activity for that account.
- Normal legitimate cloud administration.

list_azure_role_assignments
- Inspect Azure RBAC permissions.
- Security-sensitive discovery activity.

get_key_vault_secret
- Attempt to retrieve a production credential.
- Dangerous credential-access behavior.

read_sensitive_blob
- Attempt to retrieve sensitive customer data.
- Dangerous collection behavior.

send_external
- Attempt to send collected information externally.
- Dangerous exfiltration behavior.

IMPORTANT:

1. Return JSON only.
2. Do not add Markdown.
3. Do not invent tools.
4. Preserve the logical order of the requested task.
5. Include dangerous tool names when the user explicitly
   requests dangerous behavior. NEXUS will decide whether
   those actions are permitted.
6. You are a PLANNER, not the security authority.

Return this exact structure:

{{
  "tool_calls": [
    {{"tool_name": "tool_name_here"}}
  ]
}}

If no supported action applies:

{{
  "tool_calls": []
}}
""".strip()


# =========================================================
# JSON EXTRACTION
# =========================================================

def extract_json_object(
    text: str,
) -> Dict[str, Any]:
    """
    Extract one JSON object from an LLM response.
    """

    text = text.strip()


    try:

        result = json.loads(
            text
        )

        if isinstance(
            result,
            dict,
        ):

            return result


    except json.JSONDecodeError:

        pass


    start = text.find(
        "{"
    )

    end = text.rfind(
        "}"
    )


    if (
        start == -1
        or end == -1
        or end <= start
    ):

        raise ValueError(
            "Planner did not return "
            "a JSON object."
        )


    candidate = text[
        start:end + 1
    ]


    result = json.loads(
        candidate
    )


    if not isinstance(
        result,
        dict,
    ):

        raise ValueError(
            "Planner JSON response "
            "must be an object."
        )


    return result


# =========================================================
# OLLAMA / MISTRAL PLANNER
# =========================================================

def call_ollama_planner(
    user_task: str,
) -> List[Any]:

    endpoint = (
        f"{OLLAMA_BASE_URL}"
        "/api/chat"
    )


    payload = {
        "model":
            OLLAMA_MODEL,

        "stream":
            False,

        "messages": [
            {
                "role":
                    "system",

                "content":
                    build_system_prompt(),
            },
            {
                "role":
                    "user",

                "content":
                    user_task,
            },
        ],
    }


    body = json.dumps(
        payload
    ).encode(
        "utf-8"
    )


    request = urllib.request.Request(
        endpoint,

        data=body,

        headers={
            "Content-Type":
                "application/json"
        },

        method="POST",
    )


    with urllib.request.urlopen(
        request,
        timeout=30,
    ) as response:

        response_body = (
            response
            .read()
            .decode(
                "utf-8"
            )
        )


    ollama_response = json.loads(
        response_body
    )


    content = (
        ollama_response
        .get(
            "message",
            {},
        )
        .get(
            "content",
            "",
        )
    )


    planner_json = (
        extract_json_object(
            content
        )
    )


    tool_calls = (
        planner_json.get(
            "tool_calls",
            []
        )
    )


    if not isinstance(
        tool_calls,
        list,
    ):

        raise ValueError(
            "tool_calls must "
            "be a list."
        )


    return tool_calls


# =========================================================
# DETERMINISTIC FALLBACK
# =========================================================

def deterministic_fallback(
    user_task: str,
) -> List[Dict[str, str]]:
    """
    Safe deterministic planner used when the local
    Ollama model is unavailable or its response cannot
    be parsed.

    This also makes the recruiter demo reliable.
    """

    text = (
        user_task
        .lower()
        .strip()
    )


    calls = []


    # -----------------------------------------------------
    # ATTACK-CHAIN STYLE REQUEST
    # -----------------------------------------------------

    attack_indicators = [
        "send them externally",
        "send it externally",
        "exfiltrate",
        "customer records",
        "customer data",
        "database password",
        "production password",
    ]


    attack_style = any(
        indicator in text
        for indicator
        in attack_indicators
    )


    if attack_style:

        if (
            "role" in text
            or "permission" in text
            or "rbac" in text
        ):

            calls.append(
                {
                    "tool_name":
                        "list_azure_role_assignments"
                }
            )


        if (
            "password" in text
            or "secret" in text
            or "credential" in text
            or "key vault" in text
        ):

            calls.append(
                {
                    "tool_name":
                        "get_key_vault_secret"
                }
            )


        if (
            "customer" in text
            or "blob" in text
            or "sensitive" in text
            or "records" in text
        ):

            calls.append(
                {
                    "tool_name":
                        "read_sensitive_blob"
                }
            )


        if (
            "external" in text
            or "send" in text
            or "exfiltrate" in text
        ):

            calls.append(
                {
                    "tool_name":
                        "send_external"
                }
            )


        if calls:

            return calls


    # -----------------------------------------------------
    # DIRECT CREDENTIAL REQUEST
    # -----------------------------------------------------

    if (
        "password" in text
        or "secret" in text
        or "credential" in text
        or "key vault" in text
    ):

        return [
            {
                "tool_name":
                    "get_key_vault_secret"
            }
        ]


    # -----------------------------------------------------
    # RBAC DISCOVERY
    # -----------------------------------------------------

    if (
        "role assignment" in text
        or "rbac" in text
        or "permissions" in text
    ):

        calls.append(
            {
                "tool_name":
                    "list_azure_role_assignments"
            }
        )


    # -----------------------------------------------------
    # STORAGE INSPECTION
    # -----------------------------------------------------

    if (
        "storage" in text
        or "azure account" in text
        or "cloud environment" in text
    ):

        calls.append(
            {
                "tool_name":
                    "inspect_azure_storage"
            }
        )


    # -----------------------------------------------------
    # MONITORING
    # -----------------------------------------------------

    if (
        "activity" in text
        or "monitor" in text
        or "transactions" in text
        or "metrics" in text
    ):

        calls.append(
            {
                "tool_name":
                    "read_azure_monitor"
            }
        )


    return calls


# =========================================================
# MAIN PLANNER
# =========================================================

def plan_interactive_task(
    user_task: str,
) -> Dict[str, Any]:
    """
    Plan a natural-language cloud task.

    Returns canonical NEXUS requests only.
    """

    if not isinstance(
        user_task,
        str,
    ):

        raise TypeError(
            "user_task must "
            "be a string."
        )


    user_task = (
        user_task.strip()
    )


    if not user_task:

        return {
            "planner_source":
                "EMPTY",

            "tool_calls":
                [],
        }


    planner_source = (
        "OLLAMA_MISTRAL"
    )


    try:

        proposed_calls = (
            call_ollama_planner(
                user_task
            )
        )


    except (
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError,
        ValueError,
        KeyError,
    ):

        planner_source = (
            "DETERMINISTIC_FALLBACK"
        )

        proposed_calls = (
            deterministic_fallback(
                user_task
            )
        )


    # -----------------------------------------------------
    # TRUST BOUNDARY
    #
    # LLM output is not yet a valid cloud request.
    # Everything must pass through the catalog.
    # -----------------------------------------------------

    normalized_plan = (
        normalize_tool_plan(
            proposed_calls
        )
    )


    return {
        "planner_source":
            planner_source,

        "user_task":
            user_task,

        "tool_calls":
            normalized_plan,

        "proposed_count":
            len(
                proposed_calls
            ),

        "accepted_count":
            len(
                normalized_plan
            ),
    }


# =========================================================
# BACKWARD-COMPATIBLE ALIASES
# =========================================================

def plan_user_task(
    user_task: str,
) -> Dict[str, Any]:

    return (
        plan_interactive_task(
            user_task
        )
    )


def plan_task(
    user_task: str,
) -> Dict[str, Any]:

    return (
        plan_interactive_task(
            user_task
        )
    )