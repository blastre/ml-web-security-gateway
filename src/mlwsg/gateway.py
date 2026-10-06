"""Inbound policy and HTTP front door for the lab POC."""

import asyncio
import os
from html import escape
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse

from mlwsg.incidents import IncidentStore
from mlwsg.memory import LongTermMemory
from mlwsg.models import classify
from mlwsg.rules import LAB_PUBLIC, METADATA_HOSTS, inbound_reason, technique_hints
from mlwsg.ssrf_agent import SSRFAgent
from mlwsg.tools import RemoteResolver

__all__ = ["LAB_PUBLIC", "METADATA_HOSTS", "create_gateway_app", "inbound_reason", "triage"]

MODEL_PATH = Path("artifacts/models/model.joblib")
BINARY = ("logistic_regression", "random_forest", "isolation_forest")


def triage(url: str, model_path: str | Path) -> tuple[str, str | None, dict[str, float]]:
    """Fast path of the agent plan: ("allow" | "block" | "agent", reason, model scores).

    Rule violations and unanimous high scores are obvious blocks; unanimous low scores with
    no rule hint are obvious allows. Anything else (models disagree, medium score, a
    technique hint) goes to the agent.
    """
    reason = inbound_reason(url)
    if reason:
        return "block", reason, {}
    scores = {name: dict(classify(url, model_path, name)).get("ssrf", 0.0) for name in BINARY}
    if scores["logistic_regression"] >= 0.95 and scores["random_forest"] >= 0.95:
        return "block", "ML score above threshold", scores
    hinted = any(hint.technique_id for hint in technique_hints(url))
    if not hinted and all(score < 0.2 for score in scores.values()):
        return "allow", None, scores
    return "agent", None, scores


def create_gateway_app(
    db_path: str | Path = "artifacts/incidents.sqlite",
    model_path: str | Path = MODEL_PATH,
    app_url: str = "http://vuln-app:8000",
    agent: SSRFAgent | None = None,
) -> FastAPI:
    app = FastAPI(title="ML Web Security Gateway POC")
    store = IncidentStore(db_path)
    app.state.agent = agent or SSRFAgent(model_path, resolver=RemoteResolver(app_url))

    def table(headers: tuple[str, ...], rows: list[tuple]) -> str:
        head = "".join(f"<th>{escape(h)}</th>" for h in headers)
        body = "".join(
            "<tr>" + "".join(f"<td>{escape(str(cell))}</td>" for cell in row) + "</tr>"
            for row in rows
        )
        return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        incidents = []
        for item in store.list()[:50]:
            report = item["report"] or {}
            incidents.append(
                (
                    item["id"],
                    item["created_at"],
                    item["status"],
                    item["stage"],
                    item["url"],
                    item["reason"],
                    report.get("root_cause", "")[:180],
                )
            )
        decisions = [
            (
                item["id"],
                item["created_at"],
                item["verdict"],
                item["technique_id"],
                f"{item['confidence']:.2f}",
                item["url"],
                item["analysis"][:400],
            )
            for item in store.decisions(50)
        ]
        return (
            "<!doctype html><html><head><meta charset='utf-8'><title>SSRF lab incidents</title>"
            "<style>body{font:16px system-ui;max-width:1100px;margin:3rem auto;padding:0 1rem}"
            "table{border-collapse:collapse;width:100%}td,th{padding:.6rem;border:1px solid #aaa}"
            "td{overflow-wrap:anywhere}td:nth-child(-n+4){white-space:nowrap}"
            "tr:nth-child(even){background:#eee}</style></head><body>"
            "<h1>SSRF lab incidents</h1><p>Local proof-of-concept. "
            "Analysis and approval use the CLI; "
            "no patch is applied automatically.</p>"
            + table(
                ("ID", "Time", "Status", "Stage", "Target", "Reason", "Agent root cause"),
                incidents,
            )
            + "<h2>SSRF agent decisions</h2><p>Requests the fast rules could not settle. "
            "The egress guard still checks every allowed request.</p>"
            + table(
                ("ID", "Time", "Verdict", "Technique", "Confidence", "Target", "Explanation"),
                decisions,
            )
            + "</body></html>"
        )

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/fetch")
    async def fetch(url: str = Query(max_length=2048)):
        try:
            route, reason, scores = triage(url, model_path)
        except FileNotFoundError as exc:
            raise HTTPException(503, "model missing: run uv run mlwsg train") from exc
        score = scores.get("logistic_regression")
        stage = "inbound"
        decision = None
        if route == "agent":
            stage = "agent"
            try:
                result = await asyncio.to_thread(app.state.agent.analyse, url)
                decision = result.to_dict(trace=False)
            except Exception as exc:  # fail closed: an uncertain request is never waved through
                decision = {
                    "verdict": "ssrf",
                    "technique_id": "unknown",
                    "technique": "agent unavailable",
                    "confidence": 0.0,
                    "analysis": f"agent failed ({type(exc).__name__}); blocked by default",
                    "backend": "none",
                }
            if decision["verdict"] == "ssrf":
                reason = f"agent: SSRF {decision['technique_id']} ({decision['technique']})"
        if reason:
            incident_id = store.record(stage, url, reason, score)
            if decision is not None:
                store.record_decision(url, decision, incident_id)
            detail = {"stage": stage, "incident_id": incident_id, "reason": reason}
            if decision is not None:
                detail["agent"] = {
                    key: decision[key] for key in ("technique_id", "confidence", "analysis")
                }
            raise HTTPException(403, detail)
        if decision is not None:
            store.record_decision(url, decision)
        try:
            async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
                response = await client.get(f"{app_url}/fetch", params={"url": url})
        except httpx.HTTPError as exc:
            raise HTTPException(502, "testbed unavailable") from exc
        if response.status_code == 403:
            body = response.json()
            incident_id = store.record("egress", url, body.get("reason", "blocked"), score)
            raise HTTPException(
                403, {"stage": "egress", "incident_id": incident_id, "reason": body.get("reason")}
            )
        if response.status_code >= 400:
            raise HTTPException(502, "testbed fetch failed")
        return {"score": score, "route": route, "result": response.json()}

    @app.get("/incidents")
    def incidents():
        return store.list()

    @app.get("/incidents/{incident_id}")
    def incident(incident_id: int):
        try:
            return store.get(incident_id)
        except KeyError as exc:
            raise HTTPException(404, "incident not found") from exc

    @app.get("/decisions")
    def decisions():
        return store.decisions()

    return app


def _agent_from_env(model_path: str, app_url: str) -> SSRFAgent:
    memory_path = os.getenv("MLWSG_AGENT_MEMORY")
    return SSRFAgent(
        model_path,
        backend=os.getenv("MLWSG_AGENT_BACKEND", "offline"),
        sensitivity=os.getenv("MLWSG_AGENT_SENSITIVITY", "balanced"),
        resolver=RemoteResolver(app_url),
        memory=LongTermMemory(memory_path) if memory_path else None,
        effort=os.getenv("MLWSG_AGENT_EFFORT", "medium"),
    )


_MODEL = os.getenv("MLWSG_MODEL", str(MODEL_PATH))
_APP = os.getenv("MLWSG_APP", "http://vuln-app:8000")
app = create_gateway_app(
    os.getenv("MLWSG_DB", "artifacts/incidents.sqlite"),
    _MODEL,
    _APP,
    agent=_agent_from_env(_MODEL, _APP),
)
