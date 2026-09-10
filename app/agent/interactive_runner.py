"""
NEXUS Interactive Runtime Runner
================================

Natural-language task
        ↓
Mistral planner
        ↓
Trusted tool catalog
        ↓
Runtime session
        ↓
NEXUS pre-action Enforcer
        ↓
ALLOW / BLOCK
        ↓
Azure Runtime Executor
        ↓
Real Azure when approved
"""

from __future__ import annotations

import importlib
import os
import uuid

from typing import (
    Any,
    Callable,
    Optional,
)


from app.agent.interactive_planner import (
    plan_interactive_task,
)

from app.security.enforcer import (
    enforce_action,
)


# =========================================================
# EXPLANATION ENGINE
# =========================================================

try:

    from app.rag.explanation_engine import (
        explain_enforcement_decision,
    )

except ImportError:

    try:

        from app.security.explanation_engine import (
            explain_enforcement_decision,
        )

    except ImportError:

        def explain_enforcement_decision(
            request: dict,
            enforcement_result: dict,
        ):

            return {
                "summary":
                    enforcement_result.get(
                        "reason",
                        "No explanation available.",
                    )
            }


# =========================================================
# COMPONENT RESOLVER
# =========================================================

def _resolve_component(
    module_names: list[str],
    function_names: list[str],
) -> Optional[Callable]:

    for module_name in module_names:

        try:

            module = importlib.import_module(
                module_name
            )

        except ImportError:

            continue


        for function_name in function_names:

            function = getattr(
                module,
                function_name,
                None,
            )


            if callable(
                function
            ):

                return function


    return None


# =========================================================
# SESSION COMPONENTS
# =========================================================

SESSION_MODULES = [
    "app.runtime.session_state",
    "app.runtime.session_store",
    "app.runtime.session_manager",
    "app.security.session_state",
    "app.security.session_store",
    "app.session_state",
]


_CREATE_SESSION = _resolve_component(
    SESSION_MODULES,
    [
        "create_session",
        "start_session",
    ],
)


_GET_SESSION = _resolve_component(
    SESSION_MODULES,
    [
        "get_session",
    ],
)


# =========================================================
# DEMO IDENTITY / TASK
# =========================================================

DEMO_AGENT_ID = (
    "CloudOps-Agent-01"
)

DEMO_CREDENTIAL = (
    "nexus-demo-key-01"
)

DEMO_TASK_ID = (
    "task-ec2-troubleshoot"
)


# =========================================================
# SESSION ID EXTRACTION
# =========================================================

def _extract_session_id(
    created_session: Any,
) -> Optional[str]:
    """
    Extract a runtime session ID from several possible
    session-store return formats.
    """

    if created_session is None:

        return None


    # -----------------------------------------------------
    # Session store directly returned the ID
    # -----------------------------------------------------

    if isinstance(
        created_session,
        str,
    ):

        return created_session


    # -----------------------------------------------------
    # Session store returned a dictionary
    # -----------------------------------------------------

    if isinstance(
        created_session,
        dict,
    ):

        for key in [
            "session_id",
            "id",
            "runtime_session_id",
        ]:

            value = (
                created_session.get(
                    key
                )
            )


            if isinstance(
                value,
                str,
            ) and value:

                return value


        nested_session = (
            created_session.get(
                "session"
            )
        )


        if isinstance(
            nested_session,
            dict,
        ):

            for key in [
                "session_id",
                "id",
            ]:

                value = (
                    nested_session.get(
                        key
                    )
                )


                if isinstance(
                    value,
                    str,
                ) and value:

                    return value


    # -----------------------------------------------------
    # Session store returned an object
    # -----------------------------------------------------

    for attribute in [
        "session_id",
        "id",
        "runtime_session_id",
    ]:

        value = getattr(
            created_session,
            attribute,
            None,
        )


        if isinstance(
            value,
            str,
        ) and value:

            return value


    return None


# =========================================================
# SAFE SESSION LOOKUP
# =========================================================

def _lookup_session(
    session_id: Optional[str],
):

    if (
        not session_id
        or _GET_SESSION is None
    ):

        return None


    try:

        return _GET_SESSION(
            session_id
        )


    except TypeError:

        try:

            return _GET_SESSION(
                session_id=
                    session_id
            )

        except TypeError:

            return None


# =========================================================
# CREATE REAL RUNTIME SESSION
# =========================================================

def _create_runtime_session() -> str:
    """
    Create a runtime session and return the ID that the
    actual NEXUS session store recognizes.

    IMPORTANT:

    Earlier runner versions generated an ID independently
    and assumed create_session() stored that ID.

    Some session-store implementations generate their own
    ID instead.

    This function handles both designs.
    """

    if _CREATE_SESSION is None:

        raise RuntimeError(
            "NEXUS create_session() "
            "could not be located."
        )


    if _GET_SESSION is None:

        raise RuntimeError(
            "NEXUS get_session() "
            "could not be located."
        )


    candidate_session_id = (
        "nexus-"
        + uuid.uuid4().hex[:12]
    )


    # =====================================================
    # POSSIBLE SESSION-STORE SIGNATURES
    # =====================================================

    attempts = [

        # session_id + agent + task
        lambda: _CREATE_SESSION(
            session_id=
                candidate_session_id,

            agent_id=
                DEMO_AGENT_ID,

            task_id=
                DEMO_TASK_ID,
        ),


        # agent + task, store generates ID
        lambda: _CREATE_SESSION(
            agent_id=
                DEMO_AGENT_ID,

            task_id=
                DEMO_TASK_ID,
        ),


        # positional:
        # session_id, agent_id, task_id
        lambda: _CREATE_SESSION(
            candidate_session_id,
            DEMO_AGENT_ID,
            DEMO_TASK_ID,
        ),


        # positional:
        # agent_id, task_id
        lambda: _CREATE_SESSION(
            DEMO_AGENT_ID,
            DEMO_TASK_ID,
        ),


        # session_id only
        lambda: _CREATE_SESSION(
            session_id=
                candidate_session_id
        ),


        # one positional argument
        lambda: _CREATE_SESSION(
            candidate_session_id
        ),


        # session store creates everything
        lambda: _CREATE_SESSION(),
    ]


    errors = []


    # =====================================================
    # TRY EACH COMPATIBLE SIGNATURE
    # =====================================================

    for attempt in attempts:

        try:

            created_session = (
                attempt()
            )


        except TypeError as error:

            errors.append(
                str(error)
            )

            continue


        # -------------------------------------------------
        # POSSIBILITY A:
        # caller-provided ID was registered
        # -------------------------------------------------

        existing = (
            _lookup_session(
                candidate_session_id
            )
        )


        if existing is not None:

            return (
                candidate_session_id
            )


        # -------------------------------------------------
        # POSSIBILITY B:
        # store generated / returned another ID
        # -------------------------------------------------

        returned_session_id = (
            _extract_session_id(
                created_session
            )
        )


        if returned_session_id:

            existing = (
                _lookup_session(
                    returned_session_id
                )
            )


            if existing is not None:

                return (
                    returned_session_id
                )


    # =====================================================
    # NOTHING REGISTERED
    # =====================================================

    raise RuntimeError(
        "create_session() was called, but no "
        "registered runtime session could be found. "
        "Check the session-store create_session() "
        "signature."
    )


# =========================================================
# PLAN NORMALIZATION
# =========================================================

def _normalize_plan(
    plan: dict,
) -> dict:

    if not isinstance(
        plan,
        dict,
    ):

        raise TypeError(
            "Planner result must "
            "be a dictionary."
        )


    if "tool_calls" in plan:

        requests = (
            plan.get(
                "tool_calls",
                [],
            )
        )


    else:

        requests = (
            plan.get(
                "requests",
                [],
            )
        )


    if not isinstance(
        requests,
        list,
    ):

        requests = []


    plan[
        "requests"
    ] = requests


    return plan


# =========================================================
# RUNTIME TASK SCOPE
# =========================================================

def _get_runtime_scope():
    """
    Get approved services/resources for this verified task.
    """

    cloud_mode = os.getenv(
        "NEXUS_CLOUD_MODE",
        "simulation",
    ).strip().lower()


    # =====================================================
    # AZURE
    # =====================================================

    if cloud_mode == "azure":

        storage_account = os.getenv(
            "AZURE_STORAGE_ACCOUNT"
        )


        if not storage_account:

            raise RuntimeError(
                "AZURE_STORAGE_ACCOUNT "
                "is missing from .env."
            )


        return {
            "cloud_mode":
                "azure",

            "allowed_services": [
                "AzureStorage",
                "AzureMonitor",
            ],

            "allowed_resources": [
                storage_account,
            ],
        }


    # =====================================================
    # ORIGINAL SIMULATION MODE
    # =====================================================

    return {
        "cloud_mode":
            "simulation",

        "allowed_services": [
            "EC2",
            "CloudWatch",
        ],

        "allowed_resources": [
            "i-demo123",
        ],
    }


# =========================================================
# TIMELINE EVENT
# =========================================================

def _build_timeline_event(
    request: dict,
    result: dict,
    explanation: Any,
):

    tool_result = (
        result.get(
            "tool_result"
        )
    )


    backend = (
        result.get(
            "backend"
        )
    )


    if (
        backend is None
        and isinstance(
            tool_result,
            dict,
        )
    ):

        backend = (
            tool_result.get(
                "backend"
            )
        )


    if backend is None:

        if result.get(
            "executed",
            False,
        ):

            backend = (
                "SIMULATION"
            )

        else:

            backend = (
                "NOT_EXECUTED"
            )


    return {
        "tool_name":
            request.get(
                "tool_name"
            ),

        "service":
            request.get(
                "service"
            ),

        "action":
            request.get(
                "action"
            ),

        "capability":
            request.get(
                "capability"
            ),

        "resource":
            request.get(
                "resource"
            ),

        "execution_type":
            request.get(
                "execution_type"
            ),

        "decision":
            result.get(
                "decision"
            ),

        "executed":
            result.get(
                "executed",
                False,
            ),

        "reason":
            result.get(
                "reason"
            ),

        "blocked_capability":
            result.get(
                "blocked_capability"
            ),

        "backend":
            backend,

        "tool_result":
            tool_result,

        "risk":
            result.get(
                "risk"
            ),

        "attack_chain":
            result.get(
                "attack_chain"
            ),

        "containment":
            result.get(
                "containment"
            ),

        "explanation":
            explanation,
    }


# =========================================================
# MAIN INTERACTIVE RUNNER
# =========================================================

def run_interactive_task(
    user_task: str,
):
    """
    Run one natural-language cloud task through the
    complete NEXUS security pipeline.
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
            "success":
                False,

            "final_decision":
                "NO_TASK",

            "user_task":
                "",

            "timeline":
                [],
        }


    # =====================================================
    # STEP 1 — AI PLANNING
    # =====================================================

    plan = (
        plan_interactive_task(
            user_task
        )
    )


    plan = (
        _normalize_plan(
            plan
        )
    )


    # =====================================================
    # STEP 2 — VERIFIED TASK SCOPE
    # =====================================================

    scope = (
        _get_runtime_scope()
    )


    # =====================================================
    # STEP 3 — CREATE ACTUAL SESSION
    # =====================================================

    session_id = (
        _create_runtime_session()
    )


    # Extra safety check

    session_check = (
        _lookup_session(
            session_id
        )
    )


    if session_check is None:

        raise RuntimeError(
            "Runtime session creation "
            "verification failed."
        )


    # =====================================================
    # STEP 4 — PRE-ACTION ENFORCEMENT
    # =====================================================

    timeline = []

    final_decision = (
        "COMPLETED"
    )

    stopped = False


    requests = (
        plan.get(
            "requests",
            [],
        )
    )


    for request in requests:

        # -------------------------------------------------
        # REMAINING STEPS AFTER INTERVENTION
        # -------------------------------------------------

        if stopped:

            timeline.append(
                {
                    "tool_name":
                        request.get(
                            "tool_name"
                        ),

                    "service":
                        request.get(
                            "service"
                        ),

                    "action":
                        request.get(
                            "action"
                        ),

                    "capability":
                        request.get(
                            "capability"
                        ),

                    "resource":
                        request.get(
                            "resource"
                        ),

                    "decision":
                        "NOT_REACHED",

                    "executed":
                        False,

                    "reason":
                        (
                            "Previous NEXUS "
                            "intervention stopped "
                            "the remaining plan."
                        ),

                    "backend":
                        "NOT_EXECUTED",
                }
            )

            continue


        # =================================================
        # NEXUS ENFORCER
        # =================================================

        result = (
            enforce_action(

                session_id=
                    session_id,

                request=
                    request,

                allowed_services=
                    scope[
                        "allowed_services"
                    ],

                allowed_resources=
                    scope[
                        "allowed_resources"
                    ],

                identity_trusted=
                    True,

                task_trusted=
                    True,
            )
        )


        # =================================================
        # EXPLANATION
        # =================================================

        try:

            explanation = (
                explain_enforcement_decision(

                    request=
                        request,

                    enforcement_result=
                        result,
                )
            )


        except Exception:

            explanation = {
                "summary":
                    result.get(
                        "reason"
                    )
            }


        timeline.append(
            _build_timeline_event(
                request,
                result,
                explanation,
            )
        )


        # =================================================
        # STOP AFTER SECURITY INTERVENTION
        # =================================================

        decision = str(
            result.get(
                "decision",
                "",
            )
        ).upper()


        if decision in {
            "BLOCK",
            "DENY",
            "HOLD",
            "QUARANTINE",
        }:

            stopped = True

            final_decision = (
                decision
            )


    # =====================================================
    # SUMMARY
    # =====================================================

    executed_actions = [
        event

        for event
        in timeline

        if event.get(
            "executed"
        )
    ]


    blocked_actions = [
        event

        for event
        in timeline

        if event.get(
            "decision"
        )
        in {
            "BLOCK",
            "DENY",
            "HOLD",
            "QUARANTINE",
        }
    ]


    real_azure_actions = [
        event

        for event
        in timeline

        if (
            event.get(
                "backend"
            )
            == "AZURE"

            and
            event.get(
                "executed"
            )
        )
    ]


    simulated_actions = [
        event

        for event
        in timeline

        if (
            event.get(
                "backend"
            )
            == "SIMULATION"

            and
            event.get(
                "executed"
            )
        )
    ]


    return {
        "success":
            True,

        "session_id":
            session_id,

        "session_verified":
            True,

        "user_task":
            user_task,

        "cloud_mode":
            scope[
                "cloud_mode"
            ],

        "planner_source":
            plan.get(
                "planner_source"
            ),

        "plan":
            plan,

        "timeline":
            timeline,

        "final_decision":
            final_decision,

        "summary": {
            "planned_actions":
                len(
                    requests
                ),

            "executed_actions":
                len(
                    executed_actions
                ),

            "blocked_actions":
                len(
                    blocked_actions
                ),

            "real_azure_actions":
                len(
                    real_azure_actions
                ),

            "simulated_actions":
                len(
                    simulated_actions
                ),
        },
    }


# =========================================================
# COMPATIBILITY ALIASES
# =========================================================

def execute_interactive_task(
    user_task: str,
):

    return (
        run_interactive_task(
            user_task
        )
    )


def run_agent_task(
    user_task: str,
):

    return (
        run_interactive_task(
            user_task
        )
    )