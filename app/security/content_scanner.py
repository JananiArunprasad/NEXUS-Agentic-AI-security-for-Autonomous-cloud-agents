import re
from urllib.parse import urlparse


# ---------------------------------------------------------
# NEXUS Tier 1 Content Scanner
# ---------------------------------------------------------

# Domains that are considered trusted for our prototype.
ALLOWED_DOMAINS = {
    "docs.company.local",
    "internal.company.local",
}


# Invisible characters that can be used to hide instructions.
ZERO_WIDTH_CHARACTERS = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero-width no-break space
}


# High-confidence prompt-injection patterns.
HIGH_CONFIDENCE_PATTERNS = [
    (
        "instruction_override",
        re.compile(
            r"\bignore\s+(?:all\s+|any\s+|the\s+)?"
            r"(?:previous|prior)\s+"
            r"(?:instructions|rules|restrictions|task\s+restrictions)\b",
            re.IGNORECASE,
        ),
    ),

    (
        "role_override",
        re.compile(
            r"\byou\s+are\s+now\s+"
            r"(?:authorized|allowed|acting\s+as|an?|the)\b",
            re.IGNORECASE,
        ),
    ),

    (
        "secret_retrieval",
        re.compile(
            r"\b(?:retrieve|obtain|extract|read)\b"
            r".{0,80}"
            r"\b(?:password|secret|credential|api\s*key|token)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),

    (
        "concealment_instruction",
        re.compile(
            r"\b(?:do\s+not|don't)\s+"
            r"(?:tell|inform|notify|mention)\s+"
            r"(?:the\s+)?"
            r"(?:user|operator|administrator)\b",
            re.IGNORECASE,
        ),
    ),

    (
        "external_exfiltration",
        re.compile(
            r"\b(?:send|upload|transfer|exfiltrate)\b"
            r".{0,120}"
            r"https?://",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
]


# Detect URLs inside documents.
URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"]+",
    re.IGNORECASE,
)


# Detect long strings that look like Base64.
BASE64_PATTERN = re.compile(
    r"\b[A-Za-z0-9+/]{40,}={0,2}\b"
)


def is_allowed_domain(url: str) -> bool:
    """
    Check whether a URL belongs to an approved domain.
    """

    hostname = urlparse(url).hostname

    if hostname is None:
        return False

    hostname = hostname.lower()

    for allowed_domain in ALLOWED_DOMAINS:

        if (
            hostname == allowed_domain
            or hostname.endswith("." + allowed_domain)
        ):
            return True

    return False


def scan_content(content: str):
    """
    Tier 1 deterministic content scanner.

    The scanner looks for obvious prompt-injection and
    content-manipulation indicators.

    Decisions:

    ALLOW -> no Tier 1 signals detected

    HOLD -> suspicious signal detected, but not enough
            evidence for an immediate block

    BLOCK -> high-confidence malicious instruction detected
    """

    reasons = []
    score = 0

    # -----------------------------------------------------
    # Check 1: Prompt-injection phrases
    # -----------------------------------------------------

    for category, pattern in HIGH_CONFIDENCE_PATTERNS:

        match = pattern.search(content)

        if match:

            reasons.append({
                "category": category,
                "severity": "high",
                "evidence": match.group(0),
            })

            score += 50

    # -----------------------------------------------------
    # Check 2: Invisible / zero-width characters
    # -----------------------------------------------------

    detected_zero_width = [
        character
        for character in ZERO_WIDTH_CHARACTERS
        if character in content
    ]

    if detected_zero_width:

        reasons.append({
            "category": "hidden_characters",
            "severity": "medium",
            "evidence": "Zero-width character detected.",
        })

        score += 20

    # -----------------------------------------------------
    # Check 3: Suspicious Base64-like content
    # -----------------------------------------------------

    if BASE64_PATTERN.search(content):

        reasons.append({
            "category": "suspicious_encoding",
            "severity": "medium",
            "evidence": "Long Base64-like string detected.",
        })

        score += 20

    # -----------------------------------------------------
    # Check 4: External URLs
    # -----------------------------------------------------

    urls = URL_PATTERN.findall(content)

    untrusted_urls = []

    for url in urls:

        cleaned_url = url.rstrip(".,);]")

        if not is_allowed_domain(cleaned_url):
            untrusted_urls.append(cleaned_url)

    if untrusted_urls:

        reasons.append({
            "category": "untrusted_external_url",
            "severity": "medium",
            "evidence": untrusted_urls,
        })

        score += 20

    # -----------------------------------------------------
    # Final decision
    # -----------------------------------------------------

    if score >= 50:
        decision = "BLOCK"

    elif score > 0:
        decision = "HOLD"

    else:
        decision = "ALLOW"

    return {
        "tier": 1,
        "scanner": "heuristic",
        "decision": decision,
        "score": score,
        "reasons": reasons,
    }