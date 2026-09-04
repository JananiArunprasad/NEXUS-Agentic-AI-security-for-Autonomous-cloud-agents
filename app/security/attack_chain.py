from app.security.session_state import get_session


# ---------------------------------------------------------
# Attack-chain definitions
# ---------------------------------------------------------

ATTACK_CHAINS = {

    "cloud_data_exfiltration": {

        "name": "Cloud Data Exfiltration",

        "description": (
            "Agent progresses from cloud discovery "
            "to credential access, sensitive-data collection, "
            "and external exfiltration."
        ),

        "stages": [
            {
                "stage": "DISCOVERY",
                "event": "IAM:ListRoles",
            },
            {
                "stage": "CREDENTIAL_ACCESS",
                "event": "SecretsManager:GetSecretValue",
            },
            {
                "stage": "COLLECTION",
                "event": "S3:GetObject",
            },
            {
                "stage": "EXFILTRATION",
                "event": "ExternalAPI:SendData",
            },
        ],
    }
}


def match_attack_chain(
    events: list[str],
    stages: list[dict],
):
    """
    Find how far an ordered sequence of runtime events
    has progressed through an attack chain.

    Unrelated events are allowed between attack stages,
    but attack stages must occur in the correct order.
    """

    matched_stages = []

    stage_index = 0

    for event in events:

        # Stop once the entire attack chain
        # has already been matched.
        if stage_index >= len(stages):
            break

        expected_stage = stages[stage_index]

        if event == expected_stage["event"]:

            matched_stages.append({
                "stage": expected_stage["stage"],
                "event": expected_stage["event"],
            })

            stage_index += 1

    return matched_stages


def calculate_severity(
    matched_count: int,
    total_stages: int,
):
    """
    Convert attack-chain progression into
    a simple security severity level.
    """

    if matched_count == 0:
        return "NONE"

    if matched_count == 1:
        return "LOW"

    if matched_count == 2:
        return "MEDIUM"

    if matched_count < total_stages:
        return "HIGH"

    return "CRITICAL"


def analyze_session(session_id: str):
    """
    Analyze the ordered runtime history of one
    agent session for known attack-chain progression.
    """

    session = get_session(session_id)

    if session is None:

        return {
            "success": False,
            "error": "Unknown runtime session.",
        }

    events = [
        action["event"]
        for action in session["actions"]
    ]

    analyses = []

    for chain_id, chain in ATTACK_CHAINS.items():

        matched_stages = match_attack_chain(
            events,
            chain["stages"],
        )

        matched_count = len(
            matched_stages
        )

        total_stages = len(
            chain["stages"]
        )

        completion_ratio = (
            matched_count / total_stages
        )

        severity = calculate_severity(
            matched_count,
            total_stages,
        )

        complete = (
            matched_count == total_stages
        )

        next_expected_stage = None

        if not complete:

            next_expected_stage = (
                chain["stages"][matched_count]
            )

        analyses.append({
            "chain_id": chain_id,
            "chain_name": chain["name"],

            "matched_stages": matched_stages,

            "matched_count": matched_count,

            "total_stages": total_stages,

            "completion_ratio": round(
                completion_ratio,
                2
            ),

            "severity": severity,

            "complete": complete,

            "next_expected_stage":
                next_expected_stage,
        })

    # Find the chain with the highest progression.
    most_advanced = max(
        analyses,
        key=lambda item: item["completion_ratio"],
    )

    return {
        "success": True,
        "session_id": session_id,
        "events": events,
        "most_advanced_chain": most_advanced,
        "all_chain_analyses": analyses,
    }