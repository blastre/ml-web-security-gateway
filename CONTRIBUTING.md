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

The attack catalogue is `src/mlwsg/attacks.toml`; new entries need a unique `Axx` ID, declared
target and layer, plus a case in the threat model. Keep synthetic dataset families grouped across
train/test. Record model metrics honestly; this is a research POC, not a security guarantee.

Only the gateway port is published (loopback). Use dummy credentials, never scan external hosts,
and never apply an agent proposal without human review and isolated retesting. Commit
`pyproject.toml` and `uv.lock` together. Branch work stays on `phase-1-threat-model` until the
open PR is reviewed.
