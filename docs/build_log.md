# Build log: SSRF Agent POC

One entry per step: what was built, the command, the real result. Newest at the bottom.

## 1. Branch and project setup
- New branch `ssrf-agent-poc` from `main`. Old `src/`, `tests/`, Docker files removed.
  Kept: `docs/` (plan, paper, threat model), the 22-technique catalogue → `data/attacks.toml`,
  the knowledge base → `data/knowledge.toml`.
- `uv add claude-agent-sdk pydantic pydantic-settings scikit-learn joblib tldextract typer rich`.

## 2. Fast rules, egress guard, ML models
- `rules.py`: canonicalises any IP notation (hex, octal, dword, %-encoded, IPv4-mapped),
  resolves via lab DNS (`data/lab_dns.toml`) then system DNS, finds open-redirect targets and
  the WHATWG reading of backslash URLs. Fast rules block only *plain* cases (bad scheme,
  dotted internal IP, metadata hostname); egress checks every real destination.
- Check on all 22 catalogue payloads: egress blocks **22/22**; fast rules alone block 11.
- `models.py`: Logistic Regression, Random Forest (supervised) and Isolation Forest (benign
  only), 16 lexical features. `train` → 680 rows (440 attack, 240 benign).
- Observed: Isolation Forest flags unfamiliar benign URLs (github.com 0.93), so it is used as
  a signal for the agent, not in the fast-allow rule.

## 3. Agent (IDS-Agent loop)
- `agent.py` on the Claude Agent SDK: 5 tools (`classify`, `url_rules`,
  `resolve_destination`, `lookup_technique`, `memory_retrieval`), sensitivity in the system
  prompt, structured `Verdict` (pydantic). Built-in tools disabled; tools bound to the URL.
- `memory.py`: SQLite long-term memory, ranked by paper Eq. 1 (0.3·recency + 0.7·cosine).
- Live run on `http://rebind.attacker.lab/computeMetadata/v1/` (Sonnet 5.5, effort low):
  resolve_destination → url_rules → classify(RF) → **SSRF, A18 DNS rebinding, 0.96**, 13 s.

## 4. Pipeline (the flowchart)
- `pipeline.py`: fast rules → (uncertain) agent → egress guard. Fast block: LR and RF ≥ 0.95.
  Fast allow: LR and RF < 0.2 and no technique hint. Agent failure blocks (fail closed).

## 5. CLI / TUI
- `cli.py` (typer + rich): `train`, `check <url>`, `interactive`, `evaluate [csv]`,
  `memory-clear`. A live view shows the flowchart path (● stage reached, ○ skipped), the
  agent's tool calls with their observations, and a coloured decision card.
- `check http://0xa9fea9fe/...` → blocked by fast rules (LR 0.988, RF 1.0), agent not called.
- `check http://localtest.me/admin` → agent: resolve_destination → url_rules →
  **SSRF A17** (resolves to 127.0.0.1 / ::1), confidence 0.96.

## 6. Tests
- `tests/test_poc.py`: egress blocks all 22 catalogue payloads; 6 IP notations canonicalise;
  obvious cases skip the agent; uncertain → agent → egress (egress overrides a benign agent
  verdict); agent failure fails closed. Agent stubbed. `uv run pytest` → **32 passed**.

## 7. Evaluation on `data/samples.csv` (Sonnet 5.5, effort low, balanced)
- 47 URLs: the 22 catalogue attacks, 10 attacks of our own outside the catalogue
  (nip.io, localtest.me, octal dword, `http://0/`, `dict://`, private ranges, redirect in a
  shop URL…), and 15 benign URLs not used in training. `uv run ssrf-agent evaluate`.

| Method | Accuracy | F1 | Recall | False alarms |
|---|---|---|---|---|
| Majority vote (3 models) | 0.957 | 0.969 | 0.969 | 0.067 |
| Full pipeline (rules + agent + egress) | **1.0** | **1.0** | **1.0** | **0.0** |
| Agent alone (14 uncertain URLs) | 1.0 | 1.0 | 1.0 | 0.0 |

- Decided by: fast rules 33 (21 block, 12 allow), agent 14 (11 block, 3 allow), egress 0.
  0 agent errors. Each agent call takes about 10–15 s.
- The agent named the right technique for the catalogue cases it saw (A08, A15, A17, A18);
  for A20 it answered A19 (redirect to internal), a close neighbour.
- Caveat: rules and classifiers come from the same catalogue as most test attacks, and lab
  DNS is fixed. PayloadsAllTheThings (`data/patt.csv`) is the independent test still to run.
