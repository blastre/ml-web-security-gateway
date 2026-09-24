# ML-Assisted Web Security Gateway with Agentic Remediation

An academic security project that detects and prevents **SSRF (Server-Side Request Forgery)**
against web applications, combining deterministic security rules, machine learning, and
(later) an AI agent that proposes and tests remediations under human approval.

> **This repository currently contains Phase 1.**
> Phase 2 (hybrid gateway + egress guard) and Phase 3 (agentic remediation) are not
> implemented yet. Phase 1 builds the foundation they will be assembled on.

---

## 1. The project

The full system has three parts:

| Part | What it does | Status |
|---|---|---|
| **Inbound ML Security Gateway** | Normalises and analyses incoming requests, combines deterministic rules with ML models, allows legitimate traffic and blocks SSRF attempts. | Models + features ready (Phase 1); gateway itself is Phase 2 |
| **Application + Egress Protection** | A deliberately vulnerable application used as a controlled testbed, plus an egress layer that verifies *resolved* destinations before an outbound request is allowed. | Testbed ready (Phase 1); egress guard is Phase 2 |
| **Agentic Security Analysis** | Blocked requests enter an incident queue; an AI agent analyses sanitised context, identifies the root cause, proposes a patch and tests, and a human approves before isolated testing. | Phase 3 — not started |

### What Phase 1 delivers

```
Controlled vulnerable testbed
        ↓
Reproducible synthetic dataset (12,000 labelled requests, 47 traffic families)
        ↓
URL normalisation + 81 security features
        ↓
3 trained models (Logistic Regression, Random Forest, Isolation Forest)
        ↓
Evaluation (precision / recall / F1 / FPR / latency) + saved model artifacts
```

Everything runs locally, offline, and is reproducible from a fixed seed.

---

## 2. Results

Held-out test set: 3,600 requests (2,160 benign / 1,440 SSRF), stratified by traffic family.

| Model | Precision | Recall | F1 | **FPR** | ROC-AUC | Median latency |
|---|---|---|---|---|---|---|
| Logistic Regression | 0.9845 | 0.9694 | 0.9769 | 0.0102 | 0.9976 | **0.27 ms** |
| **Random Forest** | **0.9929** | 0.9681 | **0.9803** | **0.0046** | **0.9988** | 2.16 ms |
| Isolation Forest *(unsupervised)* | 0.8221 | 0.8854 | 0.8526 | 0.1278 | 0.9121 | 4.22 ms |

False Positive Rate is reported alongside the usual metrics because on an inline gateway it is
the number that decides whether the system can be deployed at all: a 1% FPR means 1 in 100
legitimate requests is blocked.

**Both supervised models detect 25 of the 27 attack families perfectly.** Every miss is
concentrated in the two families that are *designed* to be invisible to a URL-only detector:

| Family | Detection rate (RF) | Why |
|---|---|---|
| `ssrf_dns_rebinding` | 0.2500 | The hostname is public and ordinary; it only resolves to an internal address at fetch time. |
| `ssrf_redirect_chain` | 0.8060 | A third of these are seen *before* the redirect is followed, so the malicious hop is not yet visible. |

Those two families set an honest recall ceiling for Phase 1, and they are exactly the work
Phase 2's egress guard exists to do. The full breakdown, including per-family false positives
and the learned feature weights, is in **[`reports/evaluation_report.md`](reports/evaluation_report.md)**.

---

## 3. Project structure

```
.
├── src/mlwsg/
│   ├── config.py               # paths, seeds, ports, label encoding
│   ├── schema.py               # RequestRecord / DatasetSample — the shared request type
│   ├── cli.py                  # `python -m mlwsg <command>`
│   ├── net/
│   │   └── addresses.py        # permissive IP parsing + destination classification
│   ├── features/
│   │   ├── normalize.py        # URL decoding, authority parsing, obfuscation tracking
│   │   └── extractor.py        # 81 features, as a scikit-learn transformer
│   ├── dataset/
│   │   ├── vocab.py            # hostname/path/payload vocabulary
│   │   └── generator.py        # 47 traffic families, seeded generation
│   ├── models/
│   │   ├── train.py            # trains and persists the three pipelines
│   │   ├── evaluate.py         # metrics, cross-validation, latency, report rendering
│   │   └── predict.py          # SSRFDetector — the interface Phase 2 will import
│   └── testbed/
│       ├── vulnerable_app.py   # deliberately vulnerable URL-fetching application
│       ├── internal_services.py# simulated internal network + dummy metadata service
│       ├── network.py          # simulated DNS + sandbox containment
│       └── runner.py           # starts both servers
├── tests/                      # 267 tests
├── data/                       # generated dataset + metadata (committed)
├── artifacts/models/           # trained models, manifest, feature contract
├── reports/                    # evaluation report (Markdown + JSON)
├── Makefile
├── pyproject.toml
└── requirements.txt
```

---

## 4. Installation

Requires Python 3.10+.

```bash
git clone https://github.com/blastre/ml-web-security-gateway.git
cd ml-web-security-gateway

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Or simply `make install`, which does the same thing into `.venv/`.

---

## 5. Usage

### Run the whole pipeline

```bash
python -m mlwsg all          # dataset → training → evaluation
# or
make all
```

### Individual steps

```bash
# 1. Generate the dataset  →  data/ssrf_dataset.csv + data/dataset_metadata.json
python -m mlwsg generate-dataset --samples 12000 --seed 20240501

# 2. Train the models      →  artifacts/models/*.joblib
python -m mlwsg train

# 3. Evaluate              →  reports/evaluation_report.md + evaluation_results.json
python -m mlwsg evaluate
```

### Score a single request

```bash
$ python -m mlwsg predict --url 'http://0x7f000001:6379/admin' --all-models
URL: http://0x7f000001:6379/admin
  isolation_forest     BLOCK label=ssrf   score=0.9107 (5.05 ms)
  logistic_regression  BLOCK label=ssrf   score=1.0000 (0.46 ms)
  random_forest        BLOCK label=ssrf   score=1.0000 (2.36 ms)
  indicators:
    - destination is a loopback address
    - host written in hexadecimal IP notation
    - port belongs to an internal-only service
```

Inspect the extracted features for any URL:

```bash
python -m mlwsg features --url 'http://127.0.0.1.rebind.test/admin' --non-zero
```

### Run the testbed

```bash
python -m mlwsg testbed
```

This starts two loopback-only servers:

* **http://127.0.0.1:9100/** — the deliberately vulnerable application
* **http://127.0.0.1:9101/** — the simulated internal network and metadata service

Demonstrate the vulnerability:

```bash
# SSRF by IP literal — reaches an internal admin panel
curl 'http://127.0.0.1:9100/fetch?url=http://127.0.0.1:9101/admin'

# SSRF by hostname — reaches the simulated metadata service
curl 'http://127.0.0.1:9100/fetch?url=http://metadata.sim.local/metadata/v1/credentials'

# Redirect-based SSRF — the requested URL looks fine; the final hop does not
curl 'http://127.0.0.1:9100/fetch-chain?url=http://127.0.0.1:9101/admin'
```

### Run the tests

```bash
make test           # or: python -m pytest
python -m pytest -m "not slow"     # skip the tests that train models
```

---

## 6. How it works

### 6.1 Controlled testbed

`mlwsg.testbed.vulnerable_app` accepts a user-supplied URL and fetches it with **no destination
validation whatsoever** — no scheme allow-list, no private-range check, no redirect inspection.
That is the bug Phase 2 will sit in front of and Phase 3 will propose a patch for. It exposes
`/fetch`, `/preview`, `/webhook/register`, `/redirect` (an open redirect) and `/fetch-chain`.

`mlwsg.testbed.internal_services` stands in for an internal network segment: admin panels, an
application environment dump, placeholder API keys, and an instance-metadata service. Every
response is stamped `SIMULATED-DATA-FOR-SECURITY-TESTING-ONLY` and carries a proof token an
SSRF proof-of-concept can grep for.

Hostname-based SSRF works without touching `/etc/hosts`: `mlwsg.testbed.network` provides a
simulated resolver that maps names like `metadata.sim.local` and `db.internal` onto the local
internal-services port while preserving the original `Host` header.

**Safety.** See [§8](#8-safety-and-scope).

### 6.2 Dataset

`data/ssrf_dataset.csv` holds 12,000 unique labelled requests drawn from **47 traffic families**
— 20 benign traffic patterns and 27 attack techniques. Columns:

| Column | Meaning |
|---|---|
| `id` | Stable hash of the request |
| `label` | `benign` or `ssrf` |
| `family` | The technique or traffic pattern it was drawn from |
| `method`, `url`, `body` | The request itself |
| `redirect_location`, `redirect_hops` | Where this destination redirects, when observed |
| `notes` | Human-readable description |

`url` is *the URL under evaluation*: either the inbound request URL, or a user-supplied URL
extracted from it — the two things a gateway scores.

Attack families cover direct loopback and RFC1918 access, link-local/metadata targets, every
`inet_aton` IP notation (decimal, hex, octal, abbreviated), IPv6 loopback and IPv4-mapped forms,
percent- and double-encoding, userinfo confusion, wildcard-DNS embedded IPs, open-redirect
parameters, redirect chains, `file`/`gopher`/`dict`/`ftp` schemes, internal hostnames, internal
port probing, whitespace/backslash/case/unicode obfuscation, body-borne payloads, and DNS
rebinding.

Benign families are not filler. Several are deliberate **hard negatives** designed to break
naive rules:

| Hard negative | Why it is hard |
|---|---|
| `benign_public_ip_literal` | An IP in the host — but a public one |
| `benign_search` | Heavy percent-encoding, including non-ASCII — but a search box |
| `benign_public_high_port` | A non-standard port — on a public host |
| `benign_public_redirect` | A redirect — that stays public |
| `benign_userinfo_public` | Userinfo present — host still public |
| `benign_internal_url_as_text` | A real internal URL, quoted inside a bug report |
| `benign_dev_referrer` | An analytics beacon referred from `http://localhost:3000/` |

The last two genuinely contain an internal URL, so "is an internal destination mentioned
anywhere?" returns *true* for a harmless request. Separating them from a real attack requires
the interaction between *where* the URL appears and *what kind of endpoint* received it — which
is precisely where the Random Forest beats the linear model (0.0% vs 3.6% false positives on
`benign_internal_url_as_text`).

Generation is seeded: the same seed always produces the same rows, and
`data/dataset_metadata.json` records the seed, per-family counts and a SHA-256 of the CSV.

### 6.3 Preprocessing and feature engineering

**Normalisation** (`features/normalize.py`) decodes a URL the way a HTTP client would, and
records how much work that took: percent-decoding rounds, userinfo abuse, backslashes,
whitespace and control characters, malformed ports, and any URL nested in a parameter or body.
Obfuscation is treated as signal, not noise.

**Address classification** (`net/addresses.py`) reimplements the permissive `inet_aton` parsing
that libc performs, so `127.0.0.1`, `2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1` and
`[::ffff:127.0.0.1]` all collapse to the same host and the same category.

**Feature extraction** (`features/extractor.py`) produces **81 numeric features** in eight
groups: URL shape, scheme, host notation, destination classification, port, encoding and
obfuscation, embedded URLs and redirects, and request-level attributes.

The extractor is a scikit-learn transformer and is the **first step of every model pipeline**,
so a saved `.joblib` carries its own preprocessing — Phase 2 loads one file and scores a raw
request with no preprocessing code to keep in sync. It is also stateless, which rules out
train/test leakage through the features.

### 6.4 Models

| Model | Why it is here |
|---|---|
| **Logistic Regression** | Interpretable linear baseline; its coefficients read directly as "how much does this feature push a request towards SSRF". Also the fastest, at 0.27 ms/request. |
| **Random Forest** | Captures feature *interactions* the linear model cannot — notably "an internal URL is present" **and** "it sits in a fetch parameter on a fetch endpoint". |
| **Isolation Forest** | Fitted on **benign traffic only**, so it never sees a labelled attack. It answers the obvious objection to the supervised models: they can only recognise families someone thought to include. |

Training uses a 70/30 stratified split (stratified by *family*, so every technique appears on
both sides). The Isolation Forest's decision threshold is tuned on a validation split carved out
of the training data — never on the test set.

### 6.5 Evaluation

`reports/evaluation_report.md` covers:

1. Precision / recall / F1 / **FPR** / accuracy / ROC-AUC / PR-AUC on the held-out test set
2. Confusion matrices, labelled in operational terms (benign blocked, attack missed)
3. End-to-end latency — mean, median, p95, p99 — measured one request at a time, the way an
   inline gateway calls it, plus batched throughput as an upper bound
4. Stratified 5-fold cross-validation on the training split (mean ± std)
5. Isolation Forest analysis: tuned threshold vs the default `contamination` cut-off
6. **Detection rate per attack family** and **false-positive rate per benign family**
7. The learned feature weights for both supervised models
8. A section on how to read the numbers honestly

`reports/evaluation_results.json` contains the same content in machine-readable form.

---

## 7. Where the artifacts live

| Path | Contents | Committed? |
|---|---|---|
| `data/ssrf_dataset.csv` | The 12,000-sample dataset | yes |
| `data/dataset_metadata.json` | Seed, per-family counts, CSV checksum | yes |
| `artifacts/models/*.joblib` | Trained pipelines (extractor + model) | **no** — regenerate with `python -m mlwsg train` |
| `artifacts/models/manifest.json` | Training config, dataset checksum, library versions, anomaly threshold | yes |
| `artifacts/models/feature_metadata.json` | The 81 feature names, in order — the contract between training and inference | yes |
| `artifacts/models/split.json` | Exact train/test assignment | no — regenerated with the models |
| `reports/evaluation_report.md` | Human-readable evaluation | yes |
| `reports/evaluation_results.json` | Machine-readable evaluation | yes |

Model binaries are deliberately **not** committed: they are fully regenerable in a few seconds,
and a security project should not ask anyone to unpickle a binary downloaded from a repository.
The manifest and feature contract *are* committed, so the artifact layout is documented and a
stale model is detected at load time rather than silently producing wrong predictions.

Loading a model in Phase 2 will look like this:

```python
from mlwsg.models import SSRFDetector

detector = SSRFDetector.load("random_forest")
prediction = detector.predict({
    "url": "https://app.example.com/fetch?url=http://169.254.42.7/meta",
    "method": "GET",
})
prediction.label      # 'ssrf'
prediction.score      # 0.99
prediction.reasons    # ['a URL parameter points at an internal host', ...]
```

---

## 8. Safety and scope

This repository contains a deliberately vulnerable application. Three things keep that safe,
and it is worth being precise about what each one is and is not:

* **Loopback only.** The testbed binds to `127.0.0.1` and *refuses* to start on any other
  interface unless `MLWSG_ALLOW_EXTERNAL_BIND=1` is set explicitly.
* **Sandbox containment (on by default).** The vulnerable app's outbound requests are confined
  to loopback, so a deliberately broken app cannot be pointed at somebody else's server. Note
  what this is **not**: it permits exactly the traffic an egress guard would block (reaching
  internal services) and blocks the traffic an egress guard would allow (the public Internet).
  It is an operational guard rail, not a fix, and not the Phase 2 egress guard. Set
  `MLWSG_TESTBED_SANDBOX=0` for controlled experiments.
* **Nothing real is referenced.** No real external hosts are contacted. No real credentials
  exist anywhere in the repository — the "credentials" served by the metadata simulator are
  obvious placeholders that authenticate nothing. **No real cloud metadata endpoint is used**:
  the metadata scenario is served by this project's own simulated hosts, and the dataset draws
  link-local addresses at random while never emitting the well-known metadata address. Public
  hostnames in the dataset are assembled from invented brand words or the RFC 2606 `example.*`
  reservations.

Do not deploy the testbed. It exists to make SSRF observable in a lab.

---

## 9. Known limitations

* **The dataset is synthetic.** Every attack in the test set is a variation of an attack in the
  training set, so the headline scores are an upper bound on live-traffic performance.
* **The feature extractor does most of the work.** Normalisation, permissive IP parsing and
  destination classification are deterministic; the models mostly learn how to weigh those
  signals against each other. That is intentional — and it is why the per-family breakdown
  matters more than the headline F1.
* **Resolution-time attacks cannot be caught from a URL.** A hostname that looks public and
  resolves to `10.0.0.5` is invisible to any inbound URL classifier. The dataset includes this
  case honestly (`ssrf_dns_rebinding`) rather than pretending otherwise.
* **The Isolation Forest is rate-limited by rarity, not maliciousness.** It flags every
  `benign_public_ip_literal` request, because a bare public IP in the host is rare in benign
  traffic — not because it is dangerous. It is a useful novelty signal, not a blocking decision.

## 10. Reproducibility

Fixed seed `20240501` drives dataset generation, the train/test split and model initialisation.
`data/dataset_metadata.json` records a SHA-256 of the dataset; `artifacts/models/manifest.json`
records the dataset checksum, the full training configuration, and the exact versions of Python,
scikit-learn, NumPy, pandas and joblib used. Re-running `python -m mlwsg all` on the same
versions reproduces the dataset byte for byte and the reported metrics exactly.

## 11. Roadmap

* **Phase 2** — Hybrid gateway: deterministic rules combined with these models, plus an egress
  guard that classifies the *resolved* destination and closes the DNS-rebinding and
  redirect-chain gaps this phase leaves open.
* **Phase 3** — Agentic analysis: blocked requests enter an incident queue; an agent analyses
  sanitised logs and source context, identifies the root cause, proposes a patch and security
  tests, and a human approves before anything is tested in isolation.

## License

MIT — see [`LICENSE`](LICENSE).
