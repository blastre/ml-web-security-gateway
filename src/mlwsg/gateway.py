"""Inbound policy and HTTP front door for the lab POC."""

import ipaddress
import os
import socket
from html import escape
from pathlib import Path
from urllib.parse import unquote, urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse

from mlwsg.incidents import IncidentStore
from mlwsg.models import predict_url

LAB_PUBLIC = {"public.lab", "redirect.attacker.lab"}
METADATA_HOSTS = {"metadata.google.internal"}
MODEL_PATH = Path("artifacts/models/model.joblib")


def inbound_reason(url: str) -> str | None:
    if len(url) > 2048 or "\\" in url or any(ord(ch) < 32 for ch in url):
        return "ambiguous or oversized URL"
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return "invalid URL"
    if parsed.scheme not in ("http", "https") or not host or port == 0:
        return "only absolute HTTP(S) URLs are supported"
    if parsed.username or parsed.password or "@" in parsed.netloc or "%" in parsed.netloc:
        return "ambiguous URL authority"
    host = unquote(host).rstrip(".").lower()
    if host in METADATA_HOSTS:
        return "metadata hostname"
    if host in LAB_PUBLIC:
        return None
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.inet_aton(host))
        except OSError:
            return None  # Names are checked against pinned DNS results by the egress guard.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if not ip.is_global:
        return "non-public destination"
    return None


def create_gateway_app(
    db_path: str | Path = "artifacts/incidents.sqlite",
    model_path: str | Path = MODEL_PATH,
    app_url: str = "http://vuln-app:8000",
) -> FastAPI:
    app = FastAPI(title="ML Web Security Gateway POC")
    store = IncidentStore(db_path)

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        rows = []
        for item in store.list()[:50]:
            report = item["report"] or {}
            cells = (
                str(item["id"]),
                item["created_at"],
                item["status"],
                item["stage"],
                item["url"],
                item["reason"],
                report.get("root_cause", "")[:180],
            )
            rows.append(
                "<tr>" + "".join(f"<td>{escape(str(cell))}</td>" for cell in cells) + "</tr>"
            )
        return (
            "<!doctype html><html><head><meta charset='utf-8'><title>SSRF lab incidents</title>"
            "<style>body{font:16px system-ui;max-width:1100px;margin:3rem auto;padding:0 1rem}"
            "table{border-collapse:collapse;width:100%}td,th{padding:.6rem;border:1px solid #aaa}"
            "td{overflow-wrap:anywhere}td:nth-child(-n+4){white-space:nowrap}"
            "tr:nth-child(even){background:#eee}</style></head><body>"
            "<h1>SSRF lab incidents</h1><p>Local proof-of-concept. "
            "Analysis and approval use the CLI; "
            "no patch is applied automatically.</p><table><thead><tr>"
            "<th>ID</th><th>Time</th><th>Status</th><th>Stage</th><th>Target</th>"
            "<th>Reason</th><th>Agent root cause</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></body></html>"
        )

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/fetch")
    async def fetch(url: str = Query(max_length=2048)):
        reason = inbound_reason(url)
        score = None
        if reason is None:
            try:
                score = predict_url(url, model_path)
            except FileNotFoundError as exc:
                raise HTTPException(503, "model missing: run uv run mlwsg train") from exc
            if score >= 0.95:
                reason = "ML score above threshold"
        if reason:
            incident_id = store.record("inbound", url, reason, score)
            raise HTTPException(
                403, {"stage": "inbound", "incident_id": incident_id, "reason": reason}
            )
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
        return {"score": score, "result": response.json()}

    @app.get("/incidents")
    def incidents():
        return store.list()

    @app.get("/incidents/{incident_id}")
    def incident(incident_id: int):
        try:
            return store.get(incident_id)
        except KeyError as exc:
            raise HTTPException(404, "incident not found") from exc

    return app


app = create_gateway_app(
    os.getenv("MLWSG_DB", "artifacts/incidents.sqlite"),
    os.getenv("MLWSG_MODEL", str(MODEL_PATH)),
    os.getenv("MLWSG_APP", "http://vuln-app:8000"),
)
