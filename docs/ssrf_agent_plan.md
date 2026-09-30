# Custom SSRF Detection Agent, Based on IDS-Agent

*Draft for feedback* · Code: [github.com/blastre/ml-web-security-gateway](https://github.com/blastre/ml-web-security-gateway)

> **Idea.** Replace Codex, which only explained incidents after they were blocked, with our own
> agent. It checks incoming requests on the VM and decides: **is this SSRF, which technique, and why**.

## Base paper

**IDS-Agent: An LLM Agent for Explainable Intrusion Detection** (Li, Xiang, Bastian, Song, Li;
NeurIPS 2024 Workshop). An LLM agent that reasons step by step, **calls ML classifiers as tools**,
looks things up in a **knowledge base**, and returns a **verdict with an explanation**. It beat single
models and majority voting, especially when the classifiers disagreed and on unseen attacks.

## How we adapt it to SSRF

| IDS-Agent | Our agent |
|---|---|
| Input: IoT network traffic | Input: the request URL plus where it really goes (resolved IP, redirects) |
| Tools: ML classifiers | Tools: our 3 models (Logistic Regression, Random Forest, Isolation Forest) and URL rules |
| Knowledge base | Our catalogue of 22 SSRF techniques and the OWASP SSRF guidance |
| Output: attack or benign, plus reason | Output: SSRF or benign, technique, reason |

```text
Request ──► Fast rules ──── obvious case ───────────────────────► allow / block
                │
                └─ uncertain (models disagree / medium score)
                          │
                          ▼
                 AGENT: call tools → check catalogue → verdict + reason ──► allow / block + log
                                                                           │
Egress guard (always on): blocks internal / metadata IPs; the agent cannot override it
```

## What is new

- IDS-Agent was tested on IoT network traffic. We apply it to **SSRF, a web attack**, detected
  **live on a real VM**.
- Existing AI work on SSRF either **classifies URLs** (LSTM, GRU, XGBoost) or **scans source code**
  (Artemis, SSRFSeek). None uses an agent on live requests, and none checks the final destination.

## References

1. Y. Li et al., [*IDS-Agent: An LLM Agent for Explainable Intrusion Detection in IoT Networks*](https://openreview.net/pdf/d2ec624801f54649358e4d296045982ce17146d3.pdf), NeurIPS 2024 Workshop.
2. B. Kneip et al., [*Sample-Efficient LLM-Based Detection of Malicious Web Server Logs*](https://arxiv.org/abs/2606.08649) (CSIC 2010), arXiv, 2026.
3. [*Artemis: Toward Accurate Detection of Server-Side Request Forgeries through LLM-Assisted Taint Analysis*](https://arxiv.org/abs/2502.21026), Proc. ACM Program. Lang., 2025.
4. Q. Lan et al., [*Silent Egress: When Implicit Prompt Injection Makes LLM Agents Leak Without a Trace*](https://arxiv.org/abs/2602.22450), arXiv, 2026.
5. [*Benchmarking Deep Learning Models for Detecting SSRF Vulnerabilities: A Comparative Study*](https://ieeexplore.ieee.org/document/11315477/), IEEE, 2024.
