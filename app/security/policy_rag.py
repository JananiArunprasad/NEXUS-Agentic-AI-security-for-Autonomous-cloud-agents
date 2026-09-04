import json
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer


# =========================================================
# PATH CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parents[2]

POLICY_FILE = (
    BASE_DIR
    / "data"
    / "policies"
    / "nexus_policy_knowledge.json"
)

CHROMA_DIRECTORY = (
    BASE_DIR
    / "data"
    / "chroma"
)


# =========================================================
# MODEL / DATABASE CONFIGURATION
# =========================================================

MODEL_NAME = "all-MiniLM-L6-v2"

COLLECTION_NAME = "nexus_policy_knowledge_v1"


# Lazy-loaded global objects
_model = None
_client = None
_collection = None


# =========================================================
# EMBEDDING MODEL
# =========================================================

def get_embedding_model():
    """
    Load the sentence-transformer embedding model only
    when Policy RAG actually needs it.
    """

    global _model

    if _model is None:
        _model = SentenceTransformer(
            MODEL_NAME
        )

    return _model


# =========================================================
# LOAD POLICY KNOWLEDGE
# =========================================================

def load_policy_knowledge():
    """
    Load the NEXUS policy knowledge JSON file.
    """

    if not POLICY_FILE.exists():

        raise FileNotFoundError(
            f"Policy file not found: {POLICY_FILE}"
        )

    with POLICY_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:

        policies = json.load(file)

    return policies


# =========================================================
# SEED POLICY COLLECTION
# =========================================================

def seed_policy_collection(
    collection,
):
    """
    Insert NEXUS policy documents into ChromaDB.

    The collection is only seeded when it is empty.
    """

    if collection.count() > 0:
        return

    policies = load_policy_knowledge()

    model = get_embedding_model()

    documents = [
        policy["text"]
        for policy in policies
    ]

    embeddings = model.encode(
        documents,
        normalize_embeddings=True,
    ).tolist()

    ids = [
        policy["policy_id"]
        for policy in policies
    ]

    metadatas = []

    for policy in policies:

        metadatas.append(
            {
                "policy_id":
                    policy["policy_id"],

                "title":
                    policy["title"],

                "category":
                    policy["category"],

                "source":
                    policy["source"],
            }
        )

    collection.add(
        ids=ids,
        documents=documents,
        embeddings=embeddings,
        metadatas=metadatas,
    )


# =========================================================
# GET POLICY COLLECTION
# =========================================================

def get_policy_collection():
    """
    Create or load the persistent ChromaDB policy
    collection.
    """

    global _client
    global _collection

    CHROMA_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    if _client is None:

        _client = chromadb.PersistentClient(
            path=str(
                CHROMA_DIRECTORY
            )
        )

    if _collection is None:

        _collection = (
            _client.get_or_create_collection(
                name=COLLECTION_NAME,
                metadata={
                    "hnsw:space": "cosine"
                },
            )
        )

        seed_policy_collection(
            _collection
        )

    return _collection


# =========================================================
# POLICY RETRIEVAL
# =========================================================

def retrieve_policies(
    query: str,
    n_results: int = 3,
):
    """
    Retrieve security policies that are semantically
    related to the supplied runtime security context.

    IMPORTANT:
    Policy retrieval supports explanation only.

    It does NOT control ALLOW/BLOCK enforcement.
    """

    # -----------------------------------------------------
    # Validate query
    # -----------------------------------------------------

    if not query:
        return {
            "success": False,
            "query": query,
            "results": [],
            "error": "Policy query cannot be empty.",
        }

    if not query.strip():
        return {
            "success": False,
            "query": query,
            "results": [],
            "error": "Policy query cannot be empty.",
        }

    try:

        # -------------------------------------------------
        # Load database + embedding model
        # -------------------------------------------------

        collection = (
            get_policy_collection()
        )

        model = (
            get_embedding_model()
        )

        # -------------------------------------------------
        # Convert query to embedding
        # -------------------------------------------------

        query_embedding = model.encode(
            [query],
            normalize_embeddings=True,
        )[0].tolist()

        # -------------------------------------------------
        # Query ChromaDB
        # -------------------------------------------------

        result = collection.query(
            query_embeddings=[
                query_embedding
            ],

            n_results=n_results,

            include=[
                "documents",
                "metadatas",
                "distances",
            ],
        )

        # -------------------------------------------------
        # Extract results safely
        # -------------------------------------------------

        documents = []

        if result.get("documents"):
            documents = result[
                "documents"
            ][0]

        metadatas = []

        if result.get("metadatas"):
            metadatas = result[
                "metadatas"
            ][0]

        distances = []

        if result.get("distances"):
            distances = result[
                "distances"
            ][0]

        retrieved = []

        # -------------------------------------------------
        # Convert Chroma result to clean NEXUS response
        # -------------------------------------------------

        for (
            document,
            metadata,
            distance,
        ) in zip(
            documents,
            metadatas,
            distances,
        ):

            similarity = (
                1.0 - float(distance)
            )

            similarity = max(
                0.0,
                min(
                    1.0,
                    similarity,
                ),
            )

            retrieved.append(
                {
                    "policy_id":
                        metadata.get(
                            "policy_id"
                        ),

                    "title":
                        metadata.get(
                            "title"
                        ),

                    "category":
                        metadata.get(
                            "category"
                        ),

                    "source":
                        metadata.get(
                            "source"
                        ),

                    "text":
                        document,

                    "similarity":
                        round(
                            similarity,
                            4,
                        ),
                }
            )

        # -------------------------------------------------
        # Return retrieved policies
        # -------------------------------------------------

        return {
            "success": True,
            "query": query,
            "results": retrieved,
        }

    except Exception as error:

        # RAG failure must NEVER change the
        # deterministic security decision.

        return {
            "success": False,
            "query": query,
            "results": [],
            "error": str(error),
        }