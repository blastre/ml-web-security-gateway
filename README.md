# ML Web Security Gateway (research POC)

A local, synthetic demonstration of SSRF prevention: an inbound rules + ML gateway forwards
requests to a containerised app; uncertain requests go to an SSRF detection agent (adapted from
IDS-Agent) that decides whether they are SSRF, which technique, and why; the app's egress guard pins validated DNS results and checks
every redirect. Blocked requests become redacted SQLite incidents. A headless Codex run can
propose a fix for human review; it never changes code automatically. Not a production WAF.

## Architecture

```mermaid
flowchart TD
  U["Client<br/>/fetch?url=..."] --> G["Gateway triage<br/>rules + 3 ML scores"]
  M["Models<br/>trained offline"] -.-> G
  G -->|uncertain| AG["SSRF agent<br/>tools + knowledge + memory"]
  AG -->|benign| A
  AG -->|SSRF + technique + reason| I
  G -->|allow| A["vuln-app"]
  G -->|block| I[("Incident store<br/>redacted SQLite")]
  A --> E["Egress guard<br/>pinned DNS + redirect checks"]
  E -->|allow| P["Public lab service"]
  E -->|block| I
  I --> D["Dashboard / CLI"]
  D -->|analyse| X["Codex<br/>read-only"]
  X -->|report| H["Human review<br/>approve / reject"]
```

The egress guard is a **library inside `vuln-app`**, not a separate proxy or network firewall.
Only the gateway is published (`127.0.0.1:9100`). Metadata and internal services contain dummy
data; blocked destinations are not contacted. The deliberately unsafe `/unsafe-fetch` baseline
is accessible only from inside its container.

## Run

Requires [uv](https://docs.astral.sh/uv/) and Docker Compose.

```bash
uv sync
uv run mlwsg generate                 # synthetic dataset (artifacts/dataset.csv)
uv run mlwsg train                    # saved baselines + held-out metrics
uv run mlwsg memory seed              # agent long-term memory from the train split
uv run pytest                         # local checks
docker compose up --build -d          # isolated lab; only gateway published on loopback
curl -G --data-urlencode 'url=http://public.lab/ok' http://127.0.0.1:9100/fetch
curl -G --data-urlencode 'url=http://169.254.169.254/computeMetadata/v1/' http://127.0.0.1:9100/fetch
curl -G --data-urlencode 'url=http://redirect.attacker.lab/r?to=http://169.254.169.254/computeMetadata/v1/' http://127.0.0.1:9100/fetch
```

Open <http://127.0.0.1:9100/> to inspect incidents and agent decisions. Ask the agent directly
with `uv run mlwsg agent '<url>' --trace`, and benchmark it with `uv run mlwsg evaluate`; see
[docs/ssrf_agent.md](docs/ssrf_agent.md) (set `MLWSG_AGENT_BACKEND=claude` and
`ANTHROPIC_API_KEY` to use Claude as the agent's core instead of the offline policy). `uv run mlwsg incidents` lists them;
`uv run mlwsg incident 1 show` displays one. To analyse one **explicitly**, install/authenticate
Codex on the host and run `uv run mlwsg incident 1 analyse`. Review its report, then record a
human decision with `uv run mlwsg incident 1 approve` or `reject`. Approval records a decision;
there is **no automatic patch application or deployment**.

The unguarded baseline is opt-in and reachable only inside `vuln-app`. To see a dummy token leak:

```bash
docker compose exec -T vuln-app uv run --no-sync python -c 'import httpx; print(httpx.get("http://127.0.0.1:8000/unsafe-fetch", params={"url":"http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"}).json())'
```

Stop with `docker compose down`. Delete `artifacts/` to reset local data. The lab uses only dummy
credentials and internal networks; do not point it at external systems.

## Next

See [CONTRIBUTING.md](CONTRIBUTING.md) for the code map and development commands,
[docs/threat_model.md](docs/threat_model.md) for the attack catalogue,
[docs/ssrf_agent.md](docs/ssrf_agent.md) for the agent design and results, and
[docs/handover.md](docs/handover.md) for the remaining evaluation and paper work.

The dataset and held-out metrics are synthetic, not evidence of real-traffic performance.
Some catalogue variants are threat-model cases rather than live Docker fixtures. MIT licensed.
