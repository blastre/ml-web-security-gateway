# SSRF Agent (POC)

An LLM agent that decides whether a URL a web app is about to fetch is **Server-Side Request
Forgery**, **which technique** it uses, and **why**. It follows the **IDS-Agent** architecture
(Li et al., NeurIPS 2024 workshop), adapted from IoT traffic to SSRF as described in
[docs/ssrf_agent_plan.md](docs/ssrf_agent_plan.md). The agent runs on **Sonnet 5.5** by
default, and **Opus 5.5** can be selected.

```text
URL ─► Fast rules ── obvious ──────────────────────────────► allow / block
           └─ uncertain (models disagree / medium score)
                     ▼
              AGENT: reason → call tools → observe → … → verdict + technique + reason
                     ▼
Egress guard (always on): blocks internal / metadata destinations; the agent cannot override it
```

## How IDS-Agent maps to this code

| IDS-Agent (paper) | Here |
|---|---|
| Core LLM, reasoning → action → observation loop | `agent.py` (Sonnet 5.5 / Opus 5.5) |
| Data extraction and preprocessing | `models.features`: 16 lexical URL features |
| Classification tools (several ML models) | `classify`: Logistic Regression, Random Forest, Isolation Forest |
| Knowledge retrieval | `lookup_technique`: 22 catalogue techniques plus OWASP guidance (`data/knowledge.toml`) |
| Long-term memory, Eq. 1 retrieval | `memory.py`: SQLite, 0.3·recency + 0.7·cosine, correct sessions only |
| Sensitivity via the system prompt | `SSRF_AGENT_SENSITIVITY` = aggressive / balanced / conservative |
| Structured final output | pydantic `Verdict` {verdict, technique_id, confidence, reason} |
| *(new for SSRF)* | `url_rules` and `resolve_destination` (real IP, DNS rebinding, redirects, parser tricks) |

## Run

```bash
uv sync
uv run ssrf-agent train                 # train the 3 classifiers
uv run ssrf-agent interactive           # TUI: paste a URL or a sample number, `s` lists samples
uv run ssrf-agent check 'http://localtest.me/admin'
uv run ssrf-agent evaluate              # data/samples.csv through the full pipeline
uv run ssrf-agent evaluate data/patt.csv   # any CSV with url,label (1 = SSRF)
uv run pytest
```

Configuration is read from environment variables or a `.env` file (see `config.py`):

```bash
SSRF_AGENT_MODEL=claude-opus-5-5 SSRF_AGENT_SENSITIVITY=aggressive uv run ssrf-agent interactive
```

## Layout

| File | Role |
|---|---|
| `src/ssrf_agent/rules.py` | Fast rules, egress guard, IP canonicalisation, destination lookup, technique hints |
| `src/ssrf_agent/models.py` | Features and the 3 classifiers |
| `src/ssrf_agent/agent.py` | Agent: tools, system prompt, loop, verdict |
| `src/ssrf_agent/memory.py` | Long-term memory |
| `src/ssrf_agent/pipeline.py` | The flowchart above |
| `src/ssrf_agent/evaluate.py` | Metrics: majority vote vs. full pipeline vs. agent |
| `src/ssrf_agent/cli.py` | CLI and TUI |
| `data/` | Catalogue, knowledge base, lab DNS, sample test set |
| `docs/build_log.md` | What was built and measured at each step |

## Testing on PayloadsAllTheThings

Save the SSRF payloads as `data/patt.csv` with columns `url,label` (label 1), and add benign
URLs with label 0 so the false-alarm rate can be measured. Then run
`uv run ssrf-agent evaluate data/patt.csv`.

## Limits (POC)

- The classifiers are trained on the 22-technique catalogue and synthetic benign URLs.
- DNS for lab hostnames comes from `data/lab_dns.toml`; everything else uses system DNS.
- Nothing is fetched: the egress guard checks where a request *would* go.
