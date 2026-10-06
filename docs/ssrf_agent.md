# SSRF Detection Agent (IDS-Agent for SSRF)

Implementation of [ssrf_agent_plan.md](ssrf_agent_plan.md): the IDS-Agent design (Li et al.,
NeurIPS 2024 workshop) adapted from IoT network flows to SSRF requests at the gateway. For each
uncertain request the agent decides **is this SSRF, which technique, and why**.

## Pipeline

```text
Request ──► triage (gateway.py) ── obvious ──────────────────────────────► allow / block
              │ rules: inbound_reason; ML: LR and RF ≥ 0.95 → block;
              │ all three models < 0.2 and no technique hint → allow
              └─ uncertain ──► SSRFAgent.analyse (ssrf_agent.py)
                                 reason → act (tools.py) → observe … → final answer
                                 ──► allow / block, decision logged (incidents.py)
Egress guard (egress.py, always on): pins DNS, re-checks every redirect; the agent cannot override it
```

If the agent itself fails, the gateway **fails closed** and blocks the uncertain request.

## Paper → code

| IDS-Agent (Sec. 3) | This repo |
|---|---|
| Core LLM, ReAct loop: thought `r_i`, action `a_i`, observation `o_i` | `SSRFAgent._claude`: Claude (`claude-opus-5-5`, adaptive thinking) calls tools; summarised thinking is the recorded thought. `SSRFAgent._offline`: the same plan as a deterministic policy |
| Action = structured JSON (name + input) | Tool-use blocks validated against strict JSON schemas (`Toolbox.SPECS`) |
| Final answer as a JSON file | Structured output (`output_config.format`) checked by `_validate`: `verdict`, `technique_id`, `confidence`, `analysis`, `predicted_labels` |
| Data extraction (flow ID / line number) | `extract_request`; `mlwsg agent --line N` loads a dataset row |
| Preprocessing | `preprocess`: the classifiers' URL feature vector |
| Classification: top-k labels from several pretrained models | `classify` over `logistic_regression`, `random_forest`, `isolation_forest` (ssrf/benign) and `technique_forest` (top-3 catalogue IDs) |
| — (new for SSRF) | `url_rules`: inbound policy + technique hints; `resolve_destination`: canonical IP, two DNS lookups (rebinding), redirect targets in the query, WHATWG backslash re-parse |
| Knowledge retrieval (RAG over blogs/papers, ChromaDB) | `knowledge_retrieval`: TF-IDF cosine over the 22 catalogue techniques and OWASP SSRF guidance (`knowledge.toml`) |
| Long-term memory, Eq. 1: `λ1·recency + λ2·cos(E(Ō), E(O_j))`, top-5 | `memory.py` `LongTermMemory.retrieve` (hashing encoder, λ1 = λ2 = 0.5); only confirmed-correct sessions stored (`SSRFAgent.remember`) |
| Initialise LTM on a validation set | `mlwsg memory seed` (train split, 3 rows per family) |
| Aggregation (LLM over classifier results, memory, knowledge) | Claude core: the LLM itself; offline core: `aggregate()` (hard destination evidence, then a weighted score) |
| Sensitivity prompts: aggressive / balanced / conservative | `--sensitivity` → system prompt text (Claude) or decision threshold 0.35 / 0.5 / 0.65 (offline) |
| Unknown attacks: below 0.7 confidence → "Unknown" | `technique_id = "unknown"` when SSRF evidence exists but no catalogue technique fits and `technique_forest` < 0.7 |

## Safety boundaries

* Tools act only on the session's request; the model chooses tools, not hosts. `resolve_destination`
  does DNS lookups only; nothing is fetched.
* The URL and all observations are marked untrusted in the prompt; the final answer must match
  the schema, the technique must exist in the catalogue, and verdict and technique must agree.
  Anything else (refusal, invalid JSON, API error, step budget) falls back to the offline core and
  records `fallback_reason`.
* Requests use server-side refusal fallbacks (`fallbacks: "default"`, beta
  `server-side-fallback-2026-07-01`).
* Decisions are stored with the same URL/secret redaction as incidents; memory strips URLs.

## Run

```bash
uv sync --extra llm                       # anthropic SDK; omit for the offline core only
uv run mlwsg generate && uv run mlwsg train
uv run mlwsg memory seed                  # artifacts/agent_memory.sqlite
uv run mlwsg agent 'http://0xa9fea9fe/computeMetadata/v1/' --memory artifacts/agent_memory.sqlite
uv run mlwsg agent --line 3 --trace       # full thought/action/observation trace
ANTHROPIC_API_KEY=... uv run mlwsg agent --backend claude 'http://127.0.0.1.nip.io/admin'
uv run mlwsg evaluate                     # Tables 1-5 analogue → artifacts/evaluation.json
uv run mlwsg evaluate --external my_payloads.csv   # add your own test set
```

`--external` takes a CSV with `url` and `label` (1 = SSRF, 0 = benign) and an optional
`technique` column (catalogue ID). Use it for payload lists written independently of the
catalogue, such as a public SSRF payload collection, to test generalisation. Include benign URLs
too, or the false-alarm rate is undefined. If you tune rules after looking at such a list, tune on
one half and report the other.

`--resolver lab` (default for the CLI) uses deterministic lab DNS that mirrors `compose.yaml`;
`--resolver system` uses real DNS. In Docker the gateway asks `vuln-app`'s DNS-only `/resolve`
endpoint. Gateway settings: `MLWSG_AGENT_BACKEND` (`offline`/`claude`),
`MLWSG_AGENT_SENSITIVITY`, `MLWSG_AGENT_MEMORY`, `MLWSG_AGENT_EFFORT`, `ANTHROPIC_API_KEY`.

## Results (offline core, seed 20240501)

`uv run mlwsg evaluate`. *Held-out* = the grouped test split (120 attack rows from 6 catalogue
techniques the classifiers never saw, 80 benign). *Zero-day* = 15 SSRF variants outside the
catalogue (nip.io, localtest.me, Alibaba/Oracle metadata, dict://, ftp://, CGNAT, unique-local
IPv6, encoded redirects) and 7 tricky benign URLs.

| Method | Held-out acc | Held-out F1 | Held-out FAR | Technique acc | Zero-day recall | Zero-day FAR |
|---|---|---|---|---|---|---|
| logistic_regression | 0.800 | 0.800 | 0.000 | 0.400 | 0.533 | 0.000 |
| random_forest | 0.700 | 0.727 | 0.250 | 0.300 | 0.867 | 0.286 |
| isolation_forest | 0.680 | 0.644 | 0.025 | 0.390 | 1.000 | 0.571 |
| technique_forest | 0.700 | 0.727 | 0.250 | 0.300 | 0.800 | 0.286 |
| majority_vote | 0.795 | 0.796 | 0.013 | 0.395 | 0.867 | 0.286 |
| agent | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 | 0.000 |
| agent_without_knowledge | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 | 0.000 |
| agent_without_memory | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 | 0.000 |
| agent_without_destination | 0.885 | 0.897 | 0.037 | 0.885 | 0.733 | 0.286 |
| agent_url_only | 0.800 | 0.800 | 0.000 | 0.800 | 0.667 | 0.000 |
| agent_aggressive | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 | 0.000 |
| agent_conservative | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 | 0.000 |

Reading the table:

* The decisive component is **checking the final destination**, which no URL classifier in the
  related work does: removing it drops accuracy from 1.000 to 0.885 and zero-day recall to 0.733.
* Memory helps when the destination is unknown (`agent_without_destination` 0.885 vs
  `agent_url_only` 0.800). Knowledge changes the offline core's explanations, not its verdicts;
  it affects verdicts only with the Claude core.
* These numbers are **optimistic**: the rules and the knowledge base were written for the same
  catalogue the dataset is generated from, and the lab resolver is deterministic. They compare
  methods; they do not predict real-traffic performance.
* The Claude core is not in this table: it needs an API key and costs money per request. Run
  `uv run mlwsg evaluate --backend claude --limit 40` to add it.

## Limitations and next steps

* Evaluate the Claude core (and cheaper models/effort levels) and report cost and latency per
  decision; the gateway calls the agent inline only for uncertain requests.
* Real or public SSRF traffic for the held-out set; CSIC 2010 lacks SSRF, so new data is needed.
* Live memory updates need a human to confirm a verdict before `remember` is called.
* The Codex incident analysis (`agent.py`) still exists for patch proposals; the SSRF agent now
  provides the per-request explanation the plan asked for.
