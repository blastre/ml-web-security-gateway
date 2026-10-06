"""Local SSRF knowledge base retrieved by cosine similarity (IDS-Agent Sec. 3.3, RAG).

Documents are the 22 catalogue techniques plus OWASP guidance from `knowledge.toml`.
The paper embeds chunks in ChromaDB; a TF-IDF index is enough for this small corpus
and keeps retrieval offline and reproducible.
"""

import tomllib
from dataclasses import dataclass
from functools import cache
from importlib.resources import files

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from mlwsg.catalogue import load


@dataclass(frozen=True, slots=True)
class Document:
    key: str  # technique ID (A01..A22) or "guidance:<n>"
    title: str
    text: str


@cache
def documents() -> tuple[Document, ...]:
    raw = tomllib.loads(files("mlwsg").joinpath("knowledge.toml").read_text())
    docs = []
    for attack in load().attacks:
        note = raw["techniques"][attack.id]
        text = " ".join(
            (
                note["summary"],
                f"Vector: {attack.vector}. Target asset: {attack.asset}.",
                f"Indicators: {note['indicators']}",
                f"Impact: {note['impact']}",
                f"Defence: {note['defence']}",
                attack.note,
            )
        ).strip()
        docs.append(Document(attack.id, attack.technique, text))
    for index, entry in enumerate(raw["guidance"]):
        docs.append(Document(f"guidance:{index}", entry["title"], entry["text"]))
    return tuple(docs)


@cache
def _index():
    docs = documents()
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)
    matrix = vectorizer.fit_transform(f"{doc.key} {doc.title} {doc.text}" for doc in docs)
    return vectorizer, matrix


def search(query: str, k: int = 3) -> list[tuple[Document, float]]:
    """Top-k documents by cosine similarity, highest first; zero-similarity hits dropped."""
    vectorizer, matrix = _index()
    scores = cosine_similarity(vectorizer.transform([query]), matrix)[0]
    ranked = sorted(zip(documents(), scores, strict=True), key=lambda pair: -pair[1])
    return [(doc, float(score)) for doc, score in ranked[:k] if score > 0]


def technique(technique_id: str) -> Document | None:
    return next((doc for doc in documents() if doc.key == technique_id), None)
