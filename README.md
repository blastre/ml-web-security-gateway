# ML Web Security Gateway

Proof-of-concept for a research paper: a hybrid gateway that detects and blocks **SSRF** and
**cloud metadata** attacks, plus a restricted AI agent that analyses blocked incidents and
proposes fixes for human review. Runs only in a local Docker lab with dummy credentials. Not a
production WAF.

```
request → inbound gateway (rules + ML) → web app → egress guard (DNS, redirects) → allowed target
                     └──────── blocked incident → sanitised package → agent → human review
```

## Status

| Phase | Deliverable | State |
|---|---|---|
| 1 | Threat model and attack catalogue | done |
| 2 | Docker testbed and security policies | planned |
| 3 | Dataset generation | planned |
| 4 | Features and models | planned |
| 5 | Gateway and agent integration | planned |
| 6 | Evaluation and paper | planned |

## Quick start

Requires [uv](https://docs.astral.sh/uv/getting-started/installation/).

```bash
uv sync                               # create .venv with Python 3.12 and dev tools
uv run mlwsg attacks                  # list the attack catalogue
uv run mlwsg attacks --layer egress   # attacks only the egress guard can stop
uv run mlwsg assets                   # protected assets and address ranges
uv run pytest                         # verify the catalogue
```

## Layout

| Path | Contents |
|---|---|
| `docs/threat_model.md` | Assets, adversary, trust boundaries, attacks, goals (paper §Threat Model) |
| `src/mlwsg/attacks.toml` | Machine-readable attack catalogue |
| `src/mlwsg/catalogue.py` | Typed loader used by later phases |
| `tests/` | Checks that every payload targets what it claims |

## Safety

Lab use only. Never point this at systems you do not own, and never use real cloud credentials.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow. License: MIT.
