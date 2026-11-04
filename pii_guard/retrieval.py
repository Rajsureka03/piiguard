"""retrieval.py: exact lookups for detected types + hybrid search with rerank for free text."""
from __future__ import annotations

import os

from langchain_community.retrievers import BM25Retriever
from langchain_core.documents import Document

from ingest import load_chunks

CHUNKS = load_chunks()
BY_ID = {d.metadata["chunk_id"]: d for d in CHUNKS}


def _dense_retriever(k: int):
    """Chroma + local embeddings; returns None if the packages or model are unavailable."""
    try:
        from langchain_community.vectorstores import Chroma
        from langchain_huggingface import HuggingFaceEmbeddings
        emb = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
        store = Chroma.from_documents(CHUNKS, emb, collection_name="pii_kb_v3",
                                      persist_directory=".chroma")
        return store.as_retriever(search_kwargs={"k": k})
    except Exception as exc:
        print(f"[retrieval] dense search off ({type(exc).__name__}); BM25 only")
        return None


def build_retriever(k: int = 8, rerank_top: int = 4):
    bm25 = BM25Retriever.from_documents(CHUNKS)
    bm25.k = k
    dense = _dense_retriever(k) if os.getenv("USE_EMBEDDINGS") == "1" else None
    base = bm25
    if dense:
        from langchain_classic.retrievers import EnsembleRetriever
        base = EnsembleRetriever(retrievers=[bm25, dense], weights=[0.4, 0.6])  # reciprocal rank fusion
    if os.getenv("USE_RERANKER") == "1":
        try:
            from langchain_classic.retrievers import ContextualCompressionRetriever
            from langchain_classic.retrievers.document_compressors import CrossEncoderReranker
            from langchain_community.cross_encoders import HuggingFaceCrossEncoder
            ce = HuggingFaceCrossEncoder(model_name="BAAI/bge-reranker-base")
            return ContextualCompressionRetriever(base_compressor=CrossEncoderReranker(model=ce, top_n=rerank_top),
                                                  base_retriever=base)
        except Exception as exc:
            print(f"[retrieval] reranker off ({type(exc).__name__})")
    return base


RETRIEVER = build_retriever()


def retrieve(query: str, detected_types: list[str], profile: dict, already: set[str],
             max_chunks: int = 5) -> list[Document]:
    """Exact sections for detected types first, then searched chunks, personalized and deduped."""
    picked: list[Document] = []
    order = {"critical": 0, "high": 1, "medium": 2}
    for t in sorted(detected_types, key=lambda t: order[BY_ID.get(f"{t}:why:v3", CHUNKS[0]).metadata["severity"]]):
        # 1. deterministic, never missed, most severe first
        for field in ("consequences", "alternative"):
            d = BY_ID.get(f"{t}:{field}:v3")
            if d and d.metadata["chunk_id"] not in already:
                picked.append(d)
    interests = profile.get("explicit", {}).get("topics_of_interest", [])
    hits = RETRIEVER.invoke(query)                             # 2. hybrid search on redacted text
    hits.sort(key=lambda d: -sum(d.metadata.get(f"topic_{t}", False) for t in interests))  # stable boost
    for d in hits:
        if d.metadata["chunk_id"] not in already and d not in picked:
            picked.append(d)
    return picked[:max_chunks] or [BY_ID["GENERAL:why:v3"]]   # 3. never empty


def format_context(docs: list[Document]) -> str:
    return "\n".join(f"[{d.metadata['chunk_id']}] {d.page_content}" for d in docs)
