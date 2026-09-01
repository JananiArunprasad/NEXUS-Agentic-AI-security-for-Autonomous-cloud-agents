from app.security.content_scanner import (
    scan_content,
)

from app.security.embedding_scanner import (
    scan_semantic_content,
)

from app.security.llm_scanner import (
    scan_llm_content,
)


def inspect_content(content: str):
    """
    Run content through the complete
    NEXUS multi-tier security pipeline.
    """

    # =====================================================
    # TIER 1
    # =====================================================

    tier1 = scan_content(content)

    if tier1["decision"] == "BLOCK":

        return {
            "final_decision": "BLOCK",
            "reason":
                "Tier 1 detected a high-confidence threat.",
            "tier1": tier1,
            "tier2": None,
            "tier3": None,
        }

    # =====================================================
    # TIER 2
    # =====================================================

    tier2 = scan_semantic_content(content)

    if tier2["decision"] == "BLOCK":

        return {
            "final_decision": "BLOCK",
            "reason":
                "Tier 2 detected strong semantic similarity to a known attack.",
            "tier1": tier1,
            "tier2": tier2,
            "tier3": None,
        }

    # =====================================================
    # DOES TIER 3 NEED TO RUN?
    # =====================================================

    needs_tier3 = (
        tier1["decision"] == "HOLD"
        or
        tier2["decision"] == "HOLD"
    )

    if needs_tier3:

        tier3 = scan_llm_content(content)

        if tier3["decision"] == "BLOCK":

            return {
                "final_decision": "BLOCK",
                "reason":
                    "Tier 3 classified the content as suspicious.",
                "tier1": tier1,
                "tier2": tier2,
                "tier3": tier3,
            }

        if tier3["decision"] == "ALLOW":

            return {
                "final_decision": "ALLOW",
                "reason":
                    "Tier 3 resolved the ambiguous content as safe.",
                "tier1": tier1,
                "tier2": tier2,
                "tier3": tier3,
            }

        # Tier 3 could not establish safety.

        return {
            "final_decision": "HOLD",
            "reason":
                "Tier 3 could not confidently resolve the content.",
            "tier1": tier1,
            "tier2": tier2,
            "tier3": tier3,
        }

    # =====================================================
    # ALL AVAILABLE SIGNALS SAY SAFE
    # =====================================================

    return {
        "final_decision": "ALLOW",
        "reason":
            "No significant threat detected.",
        "tier1": tier1,
        "tier2": tier2,
        "tier3": None,
    }