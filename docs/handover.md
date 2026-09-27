# Handover: Phase 6 (evaluation and paper)

The current PR branch is `phase-1-threat-model`; keep subsequent work there until the PR is
reviewed. This is an educational POC, not a production WAF. Phase 1 defines the threat model;
Phases 2–5 provide an isolated Docker lab, an offline synthetic dataset, three baseline models,
a gateway with inbound and egress decisions, a read-only incident dashboard and an explicit
Codex analysis/review CLI. Use only dummy credentials and the lab networks.

## Reproduce the current demonstration

```bash
uv sync
uv run mlwsg generate --per-family 20 --seed 20240501
uv run mlwsg train
uv run pytest
docker compose up --build -d
curl -G --data-urlencode 'url=http://public.lab/ok' http://127.0.0.1:9100/fetch
curl -G --data-urlencode 'url=http://169.254.169.254/computeMetadata/v1/' http://127.0.0.1:9100/fetch
curl -G --data-urlencode 'url=http://redirect.attacker.lab/r?to=http://169.254.169.254/computeMetadata/v1/' http://127.0.0.1:9100/fetch
uv run mlwsg incidents
```

Expect public 200, direct metadata blocked inbound, and redirect blocked at egress. Open
<http://127.0.0.1:9100/> for the redacted event table. To demonstrate a baseline leak,
run the `docker compose exec vuln-app` command in the README; no baseline port is published.
For manual agent analysis: `uv run mlwsg incident ID analyse`; requires a configured `codex`
executable on the host. Then `uv run mlwsg incident ID show`, `approve` or `reject`. Approval
records the human decision; it **does not** apply a patch. `docker compose down` stops the lab.

The generated dataset has 22 attack and 14 benign families, with family-grouped train/test
splits. The fixed-seed 20-per-family run creates 720 rows (520 train, 200 held-out). Current
held-out lexical Logistic Regression: precision 1.0, recall 0.667, F1 0.8, false-positive rate
0.0; Random Forest: 0.8/0.667/0.727/0.25; Isolation Forest: 0.967/0.483/0.644/0.025.
These are **synthetic, small-sample results**, not evidence of live-traffic performance. Training
includes the public lab fixture family; do not evaluate those same URLs as independent holdout.
Model artifacts and SQLite are generated under gitignored `artifacts/`.

## Remaining work: Phase 6

1. **Evaluation protocol.** Freeze dataset generator seed and version. Record family distribution,
   class balance, label rules, and exact split (not just row-wise shuffle). Add an independent
   scenario set rather than reporting the demo URLs as new test data. Measure rule-only,
   ML-only, and hybrid confusion matrices and per-technique misses; keep the egress policy's
   allowlist effect separate from ML detection.
2. **Adversarial/egress scenarios.** Measure direct IP, alternate representations, DNS private
   answer, rebinding between requests, and redirect-hop protection. DNS rebinding currently has
   a deterministic resolver-driven test, **not** a live rebinding DNS server. The catalogue also
   includes IPv6 metadata and `file://`/`gopher://` threats that are not all executable in
   Docker; label non-executable cases as threat-model coverage, not live detection results.
3. **Timing and reproducibility.** Collect p50/p95 end-to-end gateway latency and per-stage
   overhead on fixed hardware/container versions; warm the model before measurement. Record
   sample sizes, repetitions, seed, software versions, CPU/RAM, and uncertainty. Keep denied
   requests and benign requests separate.
4. **Agent study.** With an approved provider/account, run several redacted incidents and
   assess root-cause correctness, proposed patch relevance, test quality, time/cost, and
   resistance to prompt-injection payloads. Record failures and refusals. Have a human review
   proposed changes, apply *only approved* patches in a throwaway isolated copy, then run the
   attack and benign regression cases. Current Phase 5 code intentionally does not apply or
   retest proposals.
5. **Paper.** Abstract; Introduction/contributions; Background/related work; Threat model;
   Architecture; Dataset/feature/model methodology; Experimental setup; Results (detection,
   egress ablation, latency, agent study); Discussion/limitations/ethics; Conclusion/references.
   Research questions: RQ1 detection versus baselines, RQ2 held-out family generalisation,
   RQ3 added egress protection, RQ4 request latency, RQ5 agent remediation usefulness.

## Constraints and known limitations

- The egress guard is an application-library guard, not a kernel-enforced network firewall.
  The intentionally vulnerable baseline has direct network access *inside* its container;
  it is enabled only for container-loopback callers. Other lab services have no published ports.
- The gateway is the sole published port (`127.0.0.1:9100`); it attaches an edge network for
  Docker port publishing, while app and fixtures stay on internal networks. No real cloud
  credentials or third-party targets are involved.
- `Guard` pins each validated answer through aiohttp and rechecks redirect hops; its exact
  public fixture allowlist is deliberately narrow. Lab TLS uses the checked-in **dummy**
  certificate/key for `redirect.attacker.lab`, not a general PKI.
- The optional Codex CLI is invoked from a scratch directory with a read-only tool sandbox,
  bounded output and a timeout. Its model API still needs network access; the sandbox does
  not prove that an LLM cannot be manipulated by malicious incident text.
- Synthetic variants mostly alter query/fragment; impressive scores may reflect this
  generator. Do not claim generalisation or production effectiveness from them.
