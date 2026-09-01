import json
import re
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[2]

PATTERN_FILE = (
    BASE_DIR
    / "data"
    / "attack_patterns"
    / "prompt_injection_patterns.json"
)

CHROMA_DIRECTORY = (
    BASE_DIR
    / "data"
    / "chroma"
)


# ---------------------------------------------------------
# Model + thresholds
# ---------------------------------------------------------

MODEL_NAME = "all-MiniLM-L6-v2"

BLOCK_THRESHOLD = 0.78
HOLD_THRESHOLD = 0.62


# ---------------------------------------------------------
# Lazy-loaded objects
# ---------------------------------------------------------

_model = None
_client = None
_collection = None


def get_embedding_model():
    """
    Load the embedding model only when Tier 2
    is actually used.
    """

    global _model

    if _model is None:
        _model = SentenceTransformer(MODEL_NAME)

    return _model


def load_attack_patterns():
    """
    Read our labeled attack examples from JSON.
    """

    with open(
        PATTERN_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def get_collection():
    """
    Create or open the local ChromaDB collection
    containing known prompt-injection patterns.
    """

    global _client
    global _collection

    if _collection is not None:
        return _collection

    CHROMA_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True
    )

    _client = chromadb.PersistentClient(
        path=str(CHROMA_DIRECTORY)
    )

    _collection = _client.get_or_create_collection(
        name="prompt_injection_patterns",
        metadata={
            "hnsw:space": "cosine"
        },
    )

    seed_collection(_collection)

    return _collection


def seed_collection(collection):
    """
    Add attack-pattern embeddings to ChromaDB
    if the database is currently empty.
    """

    if collection.count() > 0:
        return

    patterns = load_attack_patterns()

    model = get_embedding_model()

    texts = [
        pattern["text"]
        for pattern in patterns
    ]

    embeddings = model.encode(
        texts,
        normalize_embeddings=True,
    ).tolist()

    collection.add(
        ids=[
            pattern["id"]
            for pattern in patterns
        ],

        documents=texts,

        metadatas=[
            {
                "category": pattern["category"]
            }
            for pattern in patterns
        ],

        embeddings=embeddings,
    )


def split_content(content: str):
    """
    Break a document into smaller pieces.

    This lets NEXUS detect one malicious sentence
    hidden inside a much larger document.
    """

    pieces = re.split(
        r"[\n\r]+|(?<=[.!?])\s+",
        content
    )

    chunks = [
        piece.strip()
        for piece in pieces
        if len(piece.strip()) >= 12
    ]

    if not chunks and content.strip():
        chunks = [content.strip()]

    return chunks


def scan_semantic_content(content: str):
    """
    Tier 2 semantic scanner.

    Compare document chunks against known malicious
    attack patterns using embeddings.
    """

    chunks = split_content(content)

    if not chunks:

        return {
            "tier": 2,
            "scanner": "embedding_similarity",
            "decision": "ALLOW",
            "similarity": 0.0,
            "matched_category": None,
            "matched_pattern": None,
            "matched_content": None,
        }

    collection = get_collection()

    model = get_embedding_model()

    chunk_embeddings = model.encode(
        chunks,
        normalize_embeddings=True,
    ).tolist()

    results = collection.query(
        query_embeddings=chunk_embeddings,
        n_results=1,
        include=[
            "documents",
            "metadatas",
            "distances",
        ],
    )

    best_similarity = 0.0
    best_pattern = None
    best_category = None
    best_chunk = None

    for index, distances in enumerate(
        results["distances"]
    ):

        if not distances:
            continue

        distance = distances[0]

        similarity = 1 - distance

        if similarity > best_similarity:

            best_similarity = similarity

            best_pattern = (
                results["documents"][index][0]
            )

            best_category = (
                results["metadatas"][index][0]
                ["category"]
            )

            best_chunk = chunks[index]

    # Keep score inside a clean 0-1 range.
    best_similarity = max(
        0.0,
        min(1.0, best_similarity)
    )

    if best_similarity >= BLOCK_THRESHOLD:
        decision = "BLOCK"

    elif best_similarity >= HOLD_THRESHOLD:
        decision = "HOLD"

    else:
        decision = "ALLOW"

    return {
        "tier": 2,
        "scanner": "embedding_similarity",
        "decision": decision,
        "similarity": round(
            best_similarity,
            4
        ),
        "matched_category": best_category,
        "matched_pattern": best_pattern,
        "matched_content": best_chunk,
    }