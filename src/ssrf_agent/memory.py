"""Long-term memory of past sessions with confirmed-correct verdicts (IDS-Agent Sec. 3.3).

Retrieval ranks entries by Eq. 1:  lambda1 * recency + lambda2 * cosine(features).
"""

import json
import sqlite3
import time

import numpy as np

from ssrf_agent.config import settings
from ssrf_agent.models import features


def _connect() -> sqlite3.Connection:
    settings.artifacts_dir.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(settings.artifacts_dir / "memory.sqlite")
    db.execute(
        "CREATE TABLE IF NOT EXISTS memory (t REAL, url TEXT, features TEXT, verdict TEXT,"
        " technique_id TEXT, reason TEXT)"
    )
    return db


def add(url: str, verdict: str, technique_id: str, reason: str) -> None:
    with _connect() as db:
        db.execute(
            "INSERT INTO memory VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), url, json.dumps(features(url)), verdict, technique_id, reason),
        )


def _cosine(a: dict, b: dict) -> float:
    keys = sorted(a.keys() | b.keys())
    va, vb = (np.array([d.get(k, 0.0) for k in keys]) for d in (a, b))
    va, vb = va / (np.linalg.norm(va) or 1), vb / (np.linalg.norm(vb) or 1)
    return float(va @ vb)


def retrieve(url: str, k: int | None = None) -> list[dict]:
    with _connect() as db:
        rows = db.execute("SELECT t, url, features, verdict, technique_id, reason FROM memory")
        rows = rows.fetchall()
    if not rows:
        return []
    now, query = time.time(), features(url)
    span = max(now - t for t, *_ in rows) or 1.0
    scored = [
        (
            settings.lambda_recency * (1 - (now - t) / span)
            + settings.lambda_similarity * _cosine(query, json.loads(feats)),
            {"url": past, "verdict": verdict, "technique_id": tid, "reason": reason},
        )
        for t, past, feats, verdict, tid, reason in rows
    ]
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [item | {"score": round(score, 3)} for score, item in scored[: k or settings.memory_k]]


def size() -> int:
    with _connect() as db:
        return db.execute("SELECT COUNT(*) FROM memory").fetchone()[0]
