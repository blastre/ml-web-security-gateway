"""Durable, explicitly reviewed security incidents for the research lab."""

import json
import math
import re
import sqlite3
from pathlib import Path
from urllib.parse import parse_qsl, unquote_plus, urlsplit, urlunsplit

_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_SECRET = re.compile(
    r"(?i)\b(authorization|api[_-]?key|token|password|secret|credential|"
    r"response[_ -]?body|body)\s*[:=]\s*(?:bearer\s+)?[^\s,;]+"
)


def redact_url(url: str) -> str:
    """Discard credentials, query, and fragment before persisting or sending to an agent."""
    if not isinstance(url, str) or len(url) > 8192:
        raise ValueError("invalid URL")
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return "[invalid URL]"
    if parts.scheme not in ("http", "https") or not host:
        return "[non-HTTP URL]"
    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority += f":{port}"
    # A path can also contain credentials, e.g. /token/secret; it is not needed for review.
    return urlunsplit((parts.scheme, authority, "/[redacted]", "", ""))


def redact_text(text: str, limit: int = 512, secrets: tuple[str, ...] = ()) -> str:
    """Only bounded single-line diagnostics are retained, never URLs or credential values."""
    if not isinstance(text, str):
        raise TypeError("diagnostic must be a string")
    first_line = text.splitlines()[0] if text.splitlines() else ""
    without_urls = _URL.sub("[redacted URL]", first_line)
    without_secrets = _SECRET.sub(lambda m: f"{m.group(1)}=[redacted]", without_urls)
    for secret in secrets:
        if secret:
            without_secrets = without_secrets.replace(secret, "[redacted]")
    return without_secrets[:limit]


def _redact_report(value):
    if isinstance(value, str):
        return redact_text(value, 4000)
    if isinstance(value, list):
        return [_redact_report(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_report(item) for key, item in value.items()}
    return value


class IncidentStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    stage TEXT NOT NULL,
                    url TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    score REAL,
                    status TEXT NOT NULL DEFAULT 'blocked'
                        CHECK (status IN ('blocked', 'analysed', 'approved', 'rejected')),
                    report TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )"""
            )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.db_path, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    def record(self, stage: str, url: str, reason: str, score: float | None = None) -> int:
        if not isinstance(stage, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", stage):
            raise ValueError("invalid stage")
        if score is not None and (
            not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 1
        ):
            raise ValueError("score must be between 0 and 1")
        safe_url = redact_url(url)
        try:
            parts = urlsplit(url)
        except ValueError:
            parts = urlsplit("")
        secrets = tuple(
            token
            for _, value in parse_qsl(parts.query, keep_blank_values=False)
            for token in (value, unquote_plus(value))
            if token
        )
        with self._connect() as db:
            cursor = db.execute(
                "INSERT INTO incidents (stage, url, reason, score) VALUES (?, ?, ?, ?)",
                (stage, safe_url, redact_text(reason, secrets=secrets), score),
            )
            return int(cursor.lastrowid)

    @staticmethod
    def _as_dict(row: sqlite3.Row) -> dict:
        incident = dict(row)
        incident["report"] = json.loads(incident["report"]) if incident["report"] else None
        return incident

    def list(self) -> list[dict]:
        with self._connect() as db:
            return [
                self._as_dict(row) for row in db.execute("SELECT * FROM incidents ORDER BY id DESC")
            ]

    def get(self, id: int) -> dict:
        with self._connect() as db:
            row = db.execute("SELECT * FROM incidents WHERE id = ?", (id,)).fetchone()
        if row is None:
            raise KeyError(f"incident {id} not found")
        return self._as_dict(row)

    def _transition(self, id: int, old: str, new: str, report: str | None = None) -> None:
        with self._connect() as db:
            cursor = db.execute(
                "UPDATE incidents SET status = ?, report = COALESCE(?, report) "
                "WHERE id = ? AND status = ?",
                (new, report, id, old),
            )
            if cursor.rowcount == 0:
                exists = db.execute("SELECT 1 FROM incidents WHERE id = ?", (id,)).fetchone()
                if not exists:
                    raise KeyError(f"incident {id} not found")
                raise ValueError(f"incident {id} must be {old} before {new}")

    def set_report(self, id: int, report: dict) -> None:
        if not isinstance(report, dict):
            raise TypeError("report must be a dictionary")
        # The agent validates the report schema; this storage boundary removes URLs and secrets
        # even if a caller supplies a report directly.
        clean = _redact_report(report)
        self._transition(id, "blocked", "analysed", json.dumps(clean, ensure_ascii=True))

    def approve(self, id: int) -> None:
        self._transition(id, "analysed", "approved")

    def reject(self, id: int) -> None:
        self._transition(id, "analysed", "rejected")
