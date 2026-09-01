from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]

DOCUMENT_DIRECTORY = BASE_DIR / "data" / "documents"


def fetch_document(filename: str):
    """
    Simulates an AI agent retrieving a document.

    The document content is returned exactly as stored.
    No security scanning is performed yet.
    """

    # Basic filename safety check
    if Path(filename).name != filename:
        return {
            "success": False,
            "error": "Invalid document name.",
        }

    document_path = DOCUMENT_DIRECTORY / filename

    if not document_path.exists():
        return {
            "success": False,
            "error": "Document not found.",
        }

    content = document_path.read_text(encoding="utf-8")

    return {
        "success": True,
        "service": "DocumentStore",
        "action": "FetchDocument",
        "resource": filename,
        "content": content,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }