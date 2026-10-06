# Contributing

Python 3.12; manage the environment and run commands with [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run ruff format .
uv run ruff check .
uv run pytest
uv run mlwsg generate && uv run mlwsg train
docker compose up --build -d
docker compose down
```

## Code map

| Path | Responsibility |
|---|---|
| `attacks.toml`, `catalogue.py` | Threat-model cases and typed loader; no network calls |
| `dataset.py` → `models.py` | Generate grouped synthetic CSV; extract URL features, train/save and score baselines |
| `rules.py` | Inbound URL policy and technique hints (A01-A22) from URL shape |
| `gateway.py` | `/fetch`: triage (rules, 3 ML scores) → allow, block or ask the agent; forward allowed URLs to `vuln-app`; record blocks and agent decisions |
| `ssrf_agent.py` → `tools.py` | IDS-Agent loop (Claude or offline core) over tools: extraction, features, classifiers, rules, destination/DNS, knowledge, memory |
| `knowledge.toml`, `knowledge.py`, `memory.py` | Knowledge base (techniques + OWASP) and long-term memory (Eq. 1 retrieval) |
| `evaluate.py` | Agent vs classifiers vs majority vote; ablations, sensitivity, zero-day set |
| `testbed.py` → `egress.py` | Fake lab services; app's `/fetch` calls `Guard.fetch`, which validates/pins DNS and rechecks redirects |
| `incidents.py` → `agent.py` | Redact/store blocked events; explicit read-only Codex analysis and human decision |
| `cli.py`, `compose.yaml` | uv commands and isolated Docker wiring (`gateway` alone publishes a loopback port) |
| `tests/` | Behaviour checks for catalogue, grouped data, egress, incidents, Codex boundary and SSRF agent |

When adding an attack, update `attacks.toml`, `knowledge.toml` and `docs/threat_model.md`; give
it a unique `Axx` ID and declared target. Keep variants of a family on one side of the train/test split. For an
egress change, check both direct destinations and redirects; for incident changes, check that
secrets never reach SQLite or the agent package. Run the checks above before a PR against `main`.

Only use dummy credentials and lab targets. Model scores on generated data are not a security
guarantee; an agent proposal is never applied automatically. Commit `pyproject.toml` and
`uv.lock` together when dependencies change.
