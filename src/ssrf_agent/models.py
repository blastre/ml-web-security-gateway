"""The three classifiers the agent calls as tools (IDS-Agent Sec. 3.2, Classification).

They see only the URL's lexical shape, never its resolved address. Training data is the
22-technique catalogue plus benign URL patterns, each varied with harmless query noise.
"""

import random
import re
import tomllib
from functools import cache
from urllib.parse import urlsplit

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

from ssrf_agent import rules
from ssrf_agent.config import settings

MODELS = ("logistic_regression", "random_forest", "isolation_forest")
BENIGN = [
    "https://www.example.com/articles/introducing-our-team",
    "https://shop.example.com/products/blue-notebook",
    "https://docs.example.org/guides/getting-started",
    "https://downloads.example.net/releases/client.tar.gz",
    "https://cdn.example.net/images/banner.png",
    "http://news.example.com/world/technology",
    "https://api.example.org/v2/catalog/items?limit=10",
    "https://search.example.com/?q=weather",
    "https://help.example.net/support/contact",
    "http://public.lab/ok",
    "http://redirect.attacker.lab/r?to=http://public.lab/ok",
    "https://weather.example.com/forecast/tomorrow",
]
_KEYWORDS = ("metadata", "meta-data", "latest", "admin", "credentials", "token", "passwd")


def features(url: str) -> dict[str, float]:
    """Lexical feature vector (the paper's Preprocessing step)."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    scheme = parts.scheme.lower()
    return {
        f"scheme={scheme if scheme in ('http', 'https') else 'other'}": 1.0,
        "host_is_ip": float(rules.parse_ip(host) is not None),
        "host_digits_ratio": sum(c.isdigit() for c in host) / max(len(host), 1),
        "host_dots": host.count("."),
        "host_len": len(host),
        "host_hex": float("0x" in host),
        "host_octal": float(bool(re.search(r"(^|\.)0\d", host))),
        "host_percent": float("%" in parts.netloc),
        "host_ipv6": float(":" in host),
        "userinfo": float("@" in parts.netloc),
        "backslash": float("\\" in url),
        "explicit_port": float(":" in parts.netloc.rsplit("@", 1)[-1].strip("[]").split("]")[-1]),
        "query_url": float(bool(rules.embedded_urls(url))),
        "path_keyword": float(any(k in url.lower() for k in _KEYWORDS)),
        "internal_tld": float(host.endswith((".internal", ".local", ".lab", "localhost"))),
        "url_len": len(url),
    }


def training_rows(per_family: int = 20, seed: int = 7) -> list[tuple[str, int, str]]:
    rng = random.Random(seed)
    with (settings.data_dir / "attacks.toml").open("rb") as handle:
        attacks = [(a["payload"], 1, a["id"]) for a in tomllib.load(handle)["attacks"]]
    families = attacks + [(url, 0, "benign") for url in BENIGN]
    rows = []
    for url, label, family in families:
        for i in range(per_family):
            sep = "&" if "?" in url else "?"
            noise = "" if i == 0 else f"{sep}ref={rng.getrandbits(24):x}"
            rows.append((url + noise if not url.startswith("file:") else url, label, family))
    return rows


def train() -> dict:
    rows = training_rows()
    x = [features(url) for url, _, _ in rows]
    y = np.array([label for _, label, _ in rows])
    lr = make_pipeline(DictVectorizer(), LogisticRegression(max_iter=2000, C=0.5))
    rf = make_pipeline(DictVectorizer(), RandomForestClassifier(n_estimators=100, random_state=0))
    # Anomaly detector: trained on benign traffic only.
    iso = make_pipeline(DictVectorizer(), IsolationForest(random_state=0, contamination=0.05))
    lr.fit(x, y)
    rf.fit(x, y)
    iso.fit([f for f, label in zip(x, y, strict=True) if label == 0])
    settings.artifacts_dir.mkdir(parents=True, exist_ok=True)
    path = settings.artifacts_dir / "models.joblib"
    joblib.dump({"logistic_regression": lr, "random_forest": rf, "isolation_forest": iso}, path)
    load.cache_clear()
    return {
        "rows": len(rows),
        "attacks": int(y.sum()),
        "benign": int((y == 0).sum()),
        "path": str(path),
    }


@cache
def load() -> dict:
    path = settings.artifacts_dir / "models.joblib"
    if not path.exists():
        raise FileNotFoundError("models not trained: run `ssrf-agent train`")
    return joblib.load(path)


def ssrf_probability(url: str, model: str) -> float:
    """P(SSRF) from one classifier. The isolation forest's anomaly score is squashed to 0-1."""
    pipeline = load()[model]
    x = [features(url)]
    if model == "isolation_forest":
        return float(1 / (1 + np.exp(pipeline.decision_function(x)[0] * 20)))
    return float(pipeline.predict_proba(x)[0][1])


def scores(url: str) -> dict[str, float]:
    return {model: round(ssrf_probability(url, model), 3) for model in MODELS}
