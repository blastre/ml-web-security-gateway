"""A deliberately vulnerable URL-fetching web application.

This app is the *subject* of the project, not part of its defence.  It accepts
a user-supplied URL and fetches it with **no destination validation at all** --
no scheme allow-list, no private-range check, no redirect inspection.  That is
the bug Phase 2's gateway will sit in front of and Phase 3's agent will propose
a patch for.

Two guard rails keep it safe to run, neither of which is a fix for the
vulnerability:

* it binds to loopback and refuses any other interface unless explicitly
  overridden;
* sandbox mode confines outbound requests to loopback, so a deliberately broken
  app cannot be pointed at somebody else's server.  It still reaches the
  simulated internal services, so the vulnerability remains fully
  demonstrable -- see :mod:`mlwsg.testbed.network`.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

from mlwsg.config import TESTBED_HOST, VULNERABLE_APP_PORT
from mlwsg.testbed.network import SandboxViolation, resolve_simulated_url, sandbox_enabled

#: Maximum bytes copied back from a fetched response.
MAX_RESPONSE_BYTES = 8192
FETCH_TIMEOUT_SECONDS = 5.0

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

app = FastAPI(
    title="MLWSG Vulnerable Application",
    description=(
        "Deliberately vulnerable URL-fetching application used as the Phase 1 "
        "SSRF testbed. Loopback only. Do not deploy."
    ),
    version="1.0.0",
)


class FetchRequest(BaseModel):
    """Body for the POST fetch endpoints."""

    url: str
    method: str = "GET"


class WebhookRegistration(BaseModel):
    callback_url: str
    event: str = "ping"


def _fetch(url: str) -> dict[str, Any]:
    """Fetch *url* with no validation whatsoever -- the vulnerability itself.

    The only thing standing between this call and an arbitrary destination is
    the testbed sandbox, which is containment, not input validation.
    """
    try:
        target = resolve_simulated_url(url)
    except SandboxViolation as exc:
        return {
            "ok": False,
            "error": "sandbox_blocked",
            "detail": str(exc),
            "requested_url": url,
        }

    headers = {"User-Agent": "mlwsg-testbed/1.0"}
    if target.simulated:
        # Preserve the name the caller asked for, the way a real resolver would.
        headers["Host"] = target.original_host

    try:
        with httpx.Client(timeout=FETCH_TIMEOUT_SECONDS, follow_redirects=True) as client:
            response = client.request("GET", target.request_url, headers=headers)
    except httpx.HTTPError as exc:
        return {
            "ok": False,
            "error": "fetch_failed",
            "detail": f"{type(exc).__name__}: {exc}",
            "requested_url": url,
        }

    body = response.text[:MAX_RESPONSE_BYTES]
    return {
        "ok": True,
        "requested_url": url,
        "resolved_host": target.resolved_host,
        "simulated_dns": target.simulated,
        "status_code": response.status_code,
        "final_url": str(response.url),
        "redirected": len(response.history) > 0,
        "redirect_hops": len(response.history),
        "content_type": response.headers.get("content-type", ""),
        "body_preview": body,
        "truncated": len(response.text) > MAX_RESPONSE_BYTES,
    }


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    mode = "ON (loopback only)" if sandbox_enabled() else "OFF"
    return f"""<!doctype html>
<html><head><title>MLWSG Vulnerable App</title></head>
<body>
<h1>Vulnerable Application &mdash; SSRF Testbed</h1>
<p><strong>This application is deliberately vulnerable. Do not deploy it.</strong></p>
<p>Testbed sandbox: <code>{mode}</code></p>
<h2>Endpoints</h2>
<ul>
  <li><code>GET  /fetch?url=...</code> &mdash; fetches any URL, unvalidated (SSRF sink)</li>
  <li><code>POST /fetch</code> &mdash; same sink, URL in a JSON body</li>
  <li><code>GET  /preview?url=...</code> &mdash; link preview, extracts the page title</li>
  <li><code>POST /webhook/register</code> &mdash; verifies a callback URL by fetching it</li>
  <li><code>GET  /redirect?to=...</code> &mdash; open redirect, for redirect-based SSRF</li>
  <li><code>GET  /public-sim/hello</code> &mdash; stands in for an external resource</li>
  <li><code>GET  /healthz</code></li>
</ul>
<h2>Try it</h2>
<pre>curl 'http://127.0.0.1:9100/fetch?url=http://metadata.sim.local/metadata/v1/credentials'</pre>
</body></html>"""


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"status": "ok", "service": "vulnerable-app", "sandbox": sandbox_enabled()}


@app.get("/public-sim/hello")
def public_sim() -> dict[str, Any]:
    """A benign local resource, so allowed fetches have somewhere to go."""
    return {"message": "hello from a simulated external resource", "simulated": True}


@app.get("/fetch")
def fetch_get(url: str = Query(..., description="URL to fetch (unvalidated)")) -> JSONResponse:
    """VULNERABLE: fetches an arbitrary user-supplied URL."""
    return JSONResponse(_fetch(url))


@app.post("/fetch")
def fetch_post(payload: FetchRequest) -> JSONResponse:
    """VULNERABLE: same sink, reached through a JSON body."""
    return JSONResponse(_fetch(payload.url))


@app.get("/preview")
def preview(url: str = Query(..., description="URL to preview (unvalidated)")) -> JSONResponse:
    """VULNERABLE: link-preview feature -- fetches the URL and reads its title."""
    result = _fetch(url)
    if result.get("ok"):
        match = _TITLE_RE.search(result.get("body_preview", ""))
        result["title"] = match.group(1).strip() if match else None
        result.pop("body_preview", None)
    return JSONResponse(result)


@app.post("/webhook/register")
def register_webhook(payload: WebhookRegistration) -> JSONResponse:
    """VULNERABLE: "verifies" a webhook by fetching whatever URL was supplied."""
    result = _fetch(payload.callback_url)
    return JSONResponse(
        {
            "registered": bool(result.get("ok")),
            "event": payload.event,
            "verification": result,
        }
    )


@app.get("/redirect")
def open_redirect(to: str = Query(..., description="Redirect target (unvalidated)")) -> RedirectResponse:
    """VULNERABLE: an open redirect, the second half of redirect-based SSRF."""
    return RedirectResponse(url=to, status_code=302)


@app.get("/fetch-chain")
def fetch_chain(url: str = Query(...), via_redirect: bool = Query(True)) -> JSONResponse:
    """Fetch through this app's own open redirect, producing a real redirect chain.

    Useful for demonstrating that a destination check performed on the
    *requested* URL is not enough: the request only turns malicious after the
    redirect is followed.
    """
    if not via_redirect:
        return JSONResponse(_fetch(url))
    entry = f"http://{TESTBED_HOST}:{VULNERABLE_APP_PORT}/redirect?to={quote(url, safe='')}"
    return JSONResponse(_fetch(entry))
