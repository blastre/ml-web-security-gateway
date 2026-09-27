# Contributing

## Setup

Use [uv](https://docs.astral.sh/uv/) for everything; do not use pip or a manually created venv.

```bash
uv sync                 # install project and dev dependencies
uv add <package>        # add a runtime dependency
uv add --dev <package>  # add a dev dependency
```

Commit `pyproject.toml` and `uv.lock` together.

## Checks

Run before every push:

```bash
uv run ruff format .
uv run ruff check .
uv run pytest
```

## Adding an attack

1. Append an `[[attacks]]` entry to `src/mlwsg/attacks.toml` with the next `Axx` ID.
2. Set `resolves_to` to the address the app finally connects to, and `layers` to the boundary
   expected to stop it.
3. Update the table in `docs/threat_model.md` section 5.
4. `uv run pytest` must pass. It checks that literal payloads really reach `resolves_to`.

## Conventions

* Branch per phase (`phase-N-<topic>`), PR against `main`.
* Prefer standard library and well-known packages over custom code.
* Keep comments for the non-obvious; results and design decisions go in `docs/`, since they feed
  the paper.
* Lab only: dummy credentials, no scanning of third-party systems.
