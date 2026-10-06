"""Benchmark the SSRF agent against its classifiers and majority vote (IDS-Agent Sec. 4).

Two test sets:

* ``held-out``: the dataset's grouped test split. Its attack families are catalogue
  techniques the classifiers never saw in training.
* ``zero-day``: hand-written SSRF variants absent from the catalogue (wildcard DNS, other
  cloud metadata IPs, new schemes, encoded redirects) plus tricky benign URLs.

All destinations resolve through the deterministic `LabResolver`; nothing is fetched.
Synthetic data and rules written for the same catalogue make these numbers optimistic;
they compare methods, they do not predict real-traffic performance.
"""

import csv
import tempfile
from collections.abc import Callable
from pathlib import Path
from statistics import mean

from sklearn.metrics import precision_recall_fscore_support

from mlwsg.memory import LongTermMemory
from mlwsg.models import classify
from mlwsg.ssrf_agent import SENSITIVITIES, SSRFAgent
from mlwsg.tools import LabResolver

ZERO_DAY_ATTACKS = (
    ("http://127.0.0.1.nip.io/admin", "wildcard DNS to loopback"),
    ("http://169.254.169.254.nip.io/computeMetadata/v1/", "wildcard DNS to metadata"),
    ("http://localtest.me:6379/", "public name with loopback A record"),
    ("http://100.100.100.200/latest/meta-data/", "Alibaba Cloud metadata"),
    ("http://192.0.0.192/opc/v2/instance/", "Oracle Cloud metadata"),
    ("http://[0:0:0:0:0:ffff:127.0.0.1]/", "long-form IPv4-mapped loopback"),
    ("http://017700000001/", "octal dword loopback"),
    ("http://0x7f.1/", "hex short-form loopback"),
    ("http://0/", "zero host"),
    ("dict://10.10.0.11:6379/info", "dict:// scheme to Redis"),
    ("ftp://10.10.0.10/", "ftp:// to internal host"),
    ("http://[fd00::10]/", "IPv6 unique-local address"),
    ("http://100.64.0.1/", "carrier-grade NAT address"),
    ("https://redirect.attacker.lab/r?to=http%3A%2F%2F10.10.0.10%2Fadmin", "encoded redirect"),
    ("http://public.lab/ok?next=http://[::1]:8080/", "redirect parameter to IPv6 loopback"),
)
ZERO_DAY_BENIGN = (
    ("https://news.example.com/2026/10/06/story?id=42", "dated article"),
    ("https://cdn.example.net/v1/assets/logo.svg", "static asset"),
    ("http://93.184.216.34/", "public IP literal"),
    (
        "https://api.example.org/oauth/callback?redirect_uri=https://app.example.com/home",
        "OAuth callback with public redirect",
    ),
    ("https://shop.example.com/search?q=0x7f+octal", "search for hex-like text"),
    ("https://docs.example.org/guides/ssrf-prevention#metadata", "SSRF documentation page"),
    ("http://public.lab/ok?ref=1", "lab public page"),
)


def _binary(expected: list[int], predicted: list[int]) -> dict:
    tp = sum(e and p for e, p in zip(expected, predicted, strict=True))
    tn = sum(not e and not p for e, p in zip(expected, predicted, strict=True))
    fp = sum(not e and p for e, p in zip(expected, predicted, strict=True))
    fn = sum(e and not p for e, p in zip(expected, predicted, strict=True))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "accuracy": round((tp + tn) / len(expected), 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4)
        if precision + recall
        else 0.0,
        "far": round(fp / (fp + tn), 4) if fp + tn else 0.0,
    }


def _multiclass(expected: list[str], predicted: list[str]) -> dict:
    precision, recall, f1, _ = precision_recall_fscore_support(
        expected, predicted, average="macro", zero_division=0
    )
    return {
        "accuracy": round(mean(e == p for e, p in zip(expected, predicted, strict=True)), 4),
        "macro_precision": round(float(precision), 4),
        "macro_recall": round(float(recall), 4),
        "macro_f1": round(float(f1), 4),
    }


def load_split(dataset: str | Path, split: str, per_family: int | None = None) -> list[dict]:
    """Rows of one split as {url, label, technique}; optionally cap rows per family."""
    rows, counts = [], {}
    with Path(dataset).open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row["split"] != split:
                continue
            counts[row["family"]] = counts.get(row["family"], 0) + 1
            if per_family is not None and counts[row["family"]] > per_family:
                continue
            attack = row["label"] == "1"
            rows.append(
                {
                    "url": row["url"],
                    "label": int(attack),
                    "technique": row["family"] if attack else "benign",
                }
            )
    return rows


def load_external(path: str | Path) -> list[dict]:
    """A user-supplied test set: CSV with ``url`` and ``label`` (1 = SSRF, 0 = benign).

    An optional ``technique`` column holds a catalogue ID; otherwise attacks are scored
    as ``unknown``. Rows that are empty or longer than the agent accepts are skipped.
    """
    rows = []
    with Path(path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not {"url", "label"} <= set(reader.fieldnames or ()):
            raise ValueError("external test set needs url and label columns")
        for row in reader:
            url, label = (row["url"] or "").strip(), (row["label"] or "").strip()
            if label not in ("0", "1"):
                raise ValueError(f"label must be 0 or 1, got {label!r}")
            if not url or len(url) > 2048:
                continue
            attack = label == "1"
            technique = (row.get("technique") or "").strip() or "unknown"
            rows.append(
                {"url": url, "label": int(attack), "technique": technique if attack else "benign"}
            )
    if not rows:
        raise ValueError("external test set has no usable rows")
    return rows


def zero_day_rows() -> list[dict]:
    return [{"url": u, "label": 1, "technique": "unknown"} for u, _ in ZERO_DAY_ATTACKS] + [
        {"url": u, "label": 0, "technique": "benign"} for u, _ in ZERO_DAY_BENIGN
    ]


def seed_memory(agent: SSRFAgent, rows: list[dict]) -> int:
    """Initialise long-term memory from a validation set, keeping correct sessions only."""
    stored = 0
    for t, row in enumerate(rows):
        decision = agent.analyse(row["url"])
        label = "ssrf" if row["label"] else "benign"
        technique = row["technique"] if row["label"] else "none"
        # Deterministic timestamps keep Eq. 1's recency term reproducible.
        stored += agent.remember(row["url"], decision, label, technique, t=float(t))
    return stored


def _classifier_method(model_path: str, name: str) -> Callable[[str], tuple[int, str]]:
    def run(url: str) -> tuple[int, str]:
        flagged = dict(classify(url, model_path, name)).get("ssrf", 0.0) >= 0.5
        return int(flagged), "unknown" if flagged else "benign"

    return run


def _majority(model_path: str) -> Callable[[str], tuple[int, str]]:
    names = ("logistic_regression", "random_forest", "isolation_forest")

    def run(url: str) -> tuple[int, str]:
        votes = sum(dict(classify(url, model_path, name)).get("ssrf", 0.0) >= 0.5 for name in names)
        return int(votes >= 2), "unknown" if votes >= 2 else "benign"

    return run


def _technique_forest(model_path: str) -> Callable[[str], tuple[int, str]]:
    def run(url: str) -> tuple[int, str]:
        label = classify(url, model_path, "technique_forest", k=1)[0][0]
        return int(label != "benign"), label

    return run


def _agent_method(agent: SSRFAgent) -> Callable[[str], tuple[int, str]]:
    def run(url: str) -> tuple[int, str]:
        decision = agent.analyse(url)
        technique = "benign" if decision.verdict == "benign" else decision.technique_id
        return int(decision.verdict == "ssrf"), technique

    return run


def _score(method: Callable[[str], tuple[int, str]], rows: list[dict]) -> dict:
    predictions = [method(row["url"]) for row in rows]
    expected = [row["label"] for row in rows]
    result = {"binary": _binary(expected, [p[0] for p in predictions])}
    techniques = [row["technique"] for row in rows]
    result["technique"] = _multiclass(techniques, [p[1] for p in predictions])
    return result


def evaluate(
    dataset: str | Path,
    model_path: str | Path,
    *,
    backend: str = "offline",
    limit: int | None = None,
    memory_per_family: int = 3,
    external: str | Path | None = None,
) -> dict:
    """Run every method and ablation on each test set; return a JSON-ready report."""
    model_path = str(model_path)
    test_sets = {"held_out": load_split(dataset, "test"), "zero_day": zero_day_rows()}
    if external is not None:
        test_sets["external"] = load_external(external)
    if limit is not None:
        test_sets = {name: rows[:limit] for name, rows in test_sets.items()}
    report: dict = {
        "test_sets": {
            name: {"rows": len(rows), "attacks": sum(r["label"] for r in rows)}
            for name, rows in test_sets.items()
        },
        "methods": {},
    }
    with tempfile.TemporaryDirectory(prefix="mlwsg-eval-") as scratch:
        memory = LongTermMemory(Path(scratch) / "memory.sqlite")
        seeding = SSRFAgent(model_path, resolver=LabResolver(), memory=memory)
        report["memory_entries"] = seed_memory(
            seeding, load_split(dataset, "train", per_family=memory_per_family)
        )

        def agent(**options) -> SSRFAgent:
            options.setdefault("memory", memory)
            return SSRFAgent(model_path, backend=backend, resolver=LabResolver(), **options)

        methods = {
            "logistic_regression": _classifier_method(model_path, "logistic_regression"),
            "random_forest": _classifier_method(model_path, "random_forest"),
            "isolation_forest": _classifier_method(model_path, "isolation_forest"),
            "technique_forest": _technique_forest(model_path),
            "majority_vote": _majority(model_path),
            "agent": _agent_method(agent()),
            "agent_without_knowledge": _agent_method(agent(use_knowledge=False)),
            "agent_without_memory": _agent_method(agent(memory=None)),
            "agent_without_destination": _agent_method(agent(use_destination=False)),
            "agent_url_only": _agent_method(
                agent(use_destination=False, use_knowledge=False, memory=None)
            ),
        }
        methods |= {
            f"agent_{level}": _agent_method(agent(sensitivity=level))
            for level in SENSITIVITIES
            if level != "balanced"
        }
        for name, method in methods.items():
            report["methods"][name] = {
                set_name: _score(method, rows) for set_name, rows in test_sets.items()
            }
    report["backend"] = backend
    return report


def markdown(report: dict) -> str:
    """Render the headline comparison like IDS-Agent Table 1/2."""
    lines = [
        "| Method | Held-out acc | Held-out F1 | Held-out FAR | Technique acc | "
        "Zero-day recall | Zero-day FAR |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, scores in report["methods"].items():
        held, zero = scores["held_out"], scores["zero_day"]
        lines.append(
            f"| {name} | {held['binary']['accuracy']:.3f} | {held['binary']['f1']:.3f} | "
            f"{held['binary']['far']:.3f} | {held['technique']['accuracy']:.3f} | "
            f"{zero['binary']['recall']:.3f} | {zero['binary']['far']:.3f} |"
        )
    if "external" in report["test_sets"]:
        lines += [
            "",
            "| Method | External acc | External precision | External recall | External FAR |",
            "|---|---|---|---|---|",
        ]
        for name, scores in report["methods"].items():
            ext = scores["external"]["binary"]
            lines.append(
                f"| {name} | {ext['accuracy']:.3f} | {ext['precision']:.3f} | "
                f"{ext['recall']:.3f} | {ext['far']:.3f} |"
            )
    return "\n".join(lines)
