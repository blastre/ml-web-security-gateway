# ML Web Security Gateway (research POC)

A local, synthetic demonstration of SSRF prevention: an inbound rules + ML gateway forwards
requests to a containerised app; the app's egress guard pins validated DNS results and checks
every redirect. Blocked requests become redacted SQLite incidents. A headless Codex run can
propose a fix for human review; it never changes code automatically. Not a production WAF.

## Run

Requires [uv](https://docs.astral.sh/uv/) and Docker Compose.

```bash
uv sync
uv run mlwsg generate                 # synthetic dataset (artifacts/dataset.csv)
uv run mlwsg train                    # saved baselines + held-out metrics
uv run pytest                         # local checks
docker compose up --build -d          # isolated lab; only gateway published on loopback
curl -G --data-urlencode 'url=http://public.lab/ok' http://127.0.0.1:9100/fetch
curl -G --data-urlencode 'url=http://169.254.169.254/computeMetadata/v1/' http://127.0.0.1:9100/fetch
curl -G --data-urlencode 'url=http://redirect.attacker.lab/r?to=http://169.254.169.254/computeMetadata/v1/' http://127.0.0.1:9100/fetch
```

Open <http://127.0.0.1:9100/> to inspect incidents. `uv run mlwsg incidents` lists them;
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

## Structure

| Path | Purpose |
|---|---|
| `docs/threat_model.md` / `src/mlwsg/attacks.toml` | Phase 1 threat model and 22-case catalogue |
| `src/mlwsg/testbed.py`, `egress.py`, `compose.yaml` | Phase 2 lab and egress policy |
| `dataset.py`, `models.py` | Phases 3–4 offline data, features and baselines |
| `gateway.py`, `incidents.py`, `agent.py` | Phase 5 gateway, review and agent analysis |
| `docs/handover.md` | Phase 6 evaluation and paper handover |

The dataset and held-out metrics are synthetic; they do not establish effectiveness on real
traffic. Some catalogue variants are threat-model cases rather than live Docker fixtures. See
[CONTRIBUTING.md](CONTRIBUTING.md) for development commands. MIT licensed.
