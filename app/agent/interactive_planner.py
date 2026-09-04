import json
import os
import re
import urllib.error
import urllib.request

from dotenv import load_dotenv

from app.agent.tool_catalog import (
    build_tool_request,
)


load_dotenv()


OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://127.0.0.1:11434",
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "mistral:7b-instruct",
)


# =========================================================
# INSTANCE ID EXTRACTION
# =========================================================

def extract_instance_id(
    task: str,
):
    """
    Extract a demo/real-looking EC2 instance ID
    from the natural-language task.
    """

    match = re.search(
        r"\bi-[A-Za-z0-9-]+\b",
        task,
    )

    if match:

        return match.group(0)

    return "i-demo123"


# =========================================================
# DETERMINISTIC FALLBACK
# =========================================================

def fallback_plan(
    task: str,
):
    """
    Simple deterministic fallback if the local LLM
    is unavailable.

    This keeps the recruiter demo functional even if
    Ollama is temporarily unavailable.
    """

    lower = task.lower()

    instance_id = extract_instance_id(
        task
    )

    actions = []


    def add(
        tool_name,
        arguments=None,
    ):

        if any(
            action["tool_name"]
            == tool_name
            for action in actions
        ):
            return

        request = build_tool_request(
            tool_name,
            arguments,
        )

        if request:

            actions.append(
                request
            )


    # -----------------------------------------------------
    # NORMAL CLOUD TROUBLESHOOTING
    # -----------------------------------------------------

    if any(
        word in lower
        for word in [
            "cpu",
            "ec2",
            "instance",
            "performance",
            "troubleshoot",
            "diagnose",
        ]
    ):

        add(
            "check_ec2",
            {
                "instance_id":
                    instance_id,
            },
        )

        add(
            "read_cloudwatch",
            {
                "instance_id":
                    instance_id,
            },
        )


    if any(
        word in lower
        for word in [
            "log",
            "logs",
            "application log",
        ]
    ):

        add(
            "read_application_logs",
            {
                "instance_id":
                    instance_id,
            },
        )


    # -----------------------------------------------------
    # IAM
    # -----------------------------------------------------

    if any(
        phrase in lower
        for phrase in [
            "iam",
            "role",
            "roles",
            "permissions",
        ]
    ):

        add(
            "list_iam_roles"
        )


    # -----------------------------------------------------
    # CREDENTIAL ACCESS
    # -----------------------------------------------------

    if any(
        phrase in lower
        for phrase in [
            "secret",
            "password",
            "credential",
            "credentials",
            "database password",
        ]
    ):

        add(
            "get_secret",
            {
                "secret_name":
                    "production-db-password",
            },
        )


    # -----------------------------------------------------
    # SENSITIVE S3 DATA
    # -----------------------------------------------------

    if any(
        phrase in lower
        for phrase in [
            "customer records",
            "customer data",
            "s3",
            "bucket",
            "customer_records",
        ]
    ):

        add(
            "read_s3",
            {
                "bucket":
                    "company-sensitive-data",

                "object_name":
                    "customer_records.csv",
            },
        )


    # -----------------------------------------------------
    # EXTERNAL TRANSFER
    # -----------------------------------------------------

    if any(
        phrase in lower
        for phrase in [
            "send externally",
            "external",
            "exfiltrate",
            "transfer outside",
            "send outside",
        ]
    ):

        add(
            "send_external",
            {
                "destination":
                    "https://untrusted-example.test",
            },
        )


    # -----------------------------------------------------
    # DEFAULT SAFE TASK
    # -----------------------------------------------------

    if not actions:

        add(
            "check_ec2",
            {
                "instance_id":
                    instance_id,
            },
        )

        add(
            "read_cloudwatch",
            {
                "instance_id":
                    instance_id,
            },
        )


    return {
        "success": True,

        "planner_source":
            "DETERMINISTIC_FALLBACK",

        "summary": (
            "Fallback planner generated a "
            "structured cloud-action plan."
        ),

        "requests":
            actions,
    }


# =========================================================
# NORMALIZE LLM PLAN
# =========================================================

def normalize_llm_actions(
    raw_actions,
):
    """
    Convert untrusted LLM planner output into trusted
    NEXUS tool requests.

    Unknown tools are discarded.
    """

    requests = []

    if not isinstance(
        raw_actions,
        list,
    ):
        return requests


    for item in raw_actions[:8]:

        if not isinstance(
            item,
            dict,
        ):
            continue

        tool_name = item.get(
            "tool_name"
        )

        arguments = item.get(
            "arguments",
            {},
        )

        if not isinstance(
            arguments,
            dict,
        ):

            arguments = {}

        request = build_tool_request(
            tool_name,
            arguments,
        )

        if request is not None:

            requests.append(
                request
            )


    return requests


# =========================================================
# LLM PLANNER
# =========================================================

def plan_user_task(
    task: str,
):
    """
    Ask the local Mistral model to translate a user's
    natural-language cloud task into structured
    proposed tool requests.

    The model proposes actions only.

    It does NOT authorize or execute them.
    """

    task = task.strip()

    if not task:

        return {
            "success": False,
            "planner_source": None,
            "summary": "Task cannot be empty.",
            "requests": [],
        }


    prompt = f"""
You are the planning component of an autonomous cloud
operations agent protected by the NEXUS security system.

The user task is:

{task}

Your job is ONLY to propose a sequence of cloud tools.

You do NOT decide whether an action is safe.
You do NOT bypass security.
You do NOT execute anything.
NEXUS independently authorizes every request.

Available tools:

1. check_ec2
   arguments:
   {{"instance_id": "i-demo123"}}

2. read_cloudwatch
   arguments:
   {{"instance_id": "i-demo123"}}

3. read_application_logs
   arguments:
   {{"instance_id": "i-demo123"}}

4. list_iam_roles
   arguments:
   {{}}

5. get_secret
   arguments:
   {{"secret_name": "production-db-password"}}

6. read_s3
   arguments:
   {{
      "bucket": "company-sensitive-data",
      "object_name": "customer_records.csv"
   }}

7. send_external
   arguments:
   {{
      "destination": "https://untrusted-example.test"
   }}

Return ONLY valid JSON in this exact structure:

{{
  "summary": "short description of the proposed plan",
  "actions": [
    {{
      "tool_name": "tool name",
      "arguments": {{}}
    }}
  ]
}}

Use only the listed tools.
Do not invent tools.
Do not include markdown.
"""


    payload = {
        "model":
            OLLAMA_MODEL,

        "prompt":
            prompt,

        "stream":
            False,

        "format":
            "json",

        "options": {
            "temperature":
                0,
        },
    }


    try:

        request = urllib.request.Request(
            (
                OLLAMA_BASE_URL
                + "/api/generate"
            ),

            data=json.dumps(
                payload
            ).encode(
                "utf-8"
            ),

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

            body = json.loads(
                response.read().decode(
                    "utf-8"
                )
            )


        model_response = body.get(
            "response",
            ""
        )

        parsed = json.loads(
            model_response
        )

        requests = normalize_llm_actions(
            parsed.get(
                "actions",
                [],
            )
        )


        if not requests:

            return fallback_plan(
                task
            )


        return {
            "success": True,

            "planner_source":
                "OLLAMA_MISTRAL",

            "summary":
                parsed.get(
                    "summary",
                    "AI agent generated a cloud-action plan.",
                ),

            "requests":
                requests,
        }


    except (
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError,
        OSError,
    ):

        return fallback_plan(
            task
        )