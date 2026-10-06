"""Long-term memory of past agent sessions (IDS-Agent Sec. 3.3, Eq. 1).

An entry is phi = {t, x, R, A, O, y}: timestamp, preprocessed features, reasoning trace,
actions, observations and the final label. Only sessions whose verdict was confirmed
correct (by a dataset label or a human) are stored. Retrieval ranks entries by

    lambda1 * r(t, t_j) + lambda2 * cos(E(O_query), E(O_j)),  r = 1 - (t - t_j) / max_k (t - t_k)

and returns the top-k input/label pairs as in-context demonstrations.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from mlwsg.incidents import redact_text

# A stateless encoder: entries can be added at any time without refitting.
_ENCODER = HashingVectorizer(n_features=2**14, ngram_range=(1, 2), alternate_sign=False)


@dataclass(frozen=True, slots=True)
class Memory:
    id: int
    t: float
    features: dict
    reasoning: list[str]
    actions: list[dict]
    observations: str
    verdict: str
    technique_id: str
    score: float = 0.0


class LongTermMemory:
    def __init__(self, path: str | Path, lambda1: float = 0.5, lambda2: float = 0.5):
        self.path = Path(path)
        self.lambda1, self.lambda2 = lambda1, lambda2
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS memories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    t REAL NOT NULL,
                    features TEXT NOT NULL,
                    reasoning TEXT NOT NULL,
                    actions TEXT NOT NULL,
                    observations TEXT NOT NULL,
                    verdict TEXT NOT NULL CHECK (verdict IN ('ssrf', 'benign')),
                    technique_id TEXT NOT NULL
                )"""
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)

    def add(
        self,
        *,
        features: dict,
        reasoning: list[str],
        actions: list[dict],
        observations: str,
        verdict: str,
        technique_id: str,
        t: float | None = None,
    ) -> int:
        """Store one confirmed-correct session. URLs and secrets are stripped from text."""
        if verdict not in ("ssrf", "benign"):
            raise ValueError("memory verdict must be ssrf or benign")
        clean = [redact_text(line, 2000) for line in reasoning]
        with self._connect() as db:
            cursor = db.execute(
                "INSERT INTO memories "
                "(t, features, reasoning, actions, observations, verdict, technique_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    time.time() if t is None else t,
                    json.dumps(features),
                    json.dumps(clean),
                    json.dumps(actions),
                    redact_text(observations.replace("\n", " "), 8000),
                    verdict,
                    technique_id,
                ),
            )
            return int(cursor.lastrowid)

    def __len__(self) -> int:
        with self._connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM memories").fetchone()[0])

    def retrieve(self, observations: str, k: int = 5, now: float | None = None) -> list[Memory]:
        """Top-k memories by weighted recency and observation similarity (Eq. 1)."""
        with self._connect() as db:
            rows = db.execute(
                "SELECT id, t, features, reasoning, actions, observations, verdict, technique_id "
                "FROM memories"
            ).fetchall()
        if not rows:
            return []
        now = time.time() if now is None else now
        oldest = max(now - row[1] for row in rows) or 1.0
        query = redact_text(observations.replace("\n", " "), 8000)
        similarity = cosine_similarity(
            _ENCODER.transform([query]), _ENCODER.transform([row[5] for row in rows])
        )[0]
        scored = []
        for row, cos in zip(rows, similarity, strict=True):
            recency = 1 - (now - row[1]) / oldest
            scored.append((self.lambda1 * recency + self.lambda2 * float(cos), row))
        scored.sort(key=lambda pair: -pair[0])
        return [
            Memory(
                id=row[0],
                t=row[1],
                features=json.loads(row[2]),
                reasoning=json.loads(row[3]),
                actions=json.loads(row[4]),
                observations=row[5],
                verdict=row[6],
                technique_id=row[7],
                score=round(score, 4),
            )
            for score, row in scored[:k]
        ]
