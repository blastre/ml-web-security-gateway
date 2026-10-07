"""Run a labelled CSV (`url,label[,technique]`, 1 = SSRF) through the full pipeline and
compare it with majority vote of the three classifiers."""

import asyncio
import csv
import json
from collections import Counter
from pathlib import Path

from sklearn.metrics import accuracy_score, confusion_matrix, f1_score

from ssrf_agent import memory, models, pipeline
from ssrf_agent.config import settings


def load_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = [r for r in csv.DictReader(handle) if r.get("url", "").strip()]
    for row in rows:
        row["url"], row["label"] = row["url"].strip(), int(row["label"])
    return rows


def metrics(y_true: list[int], y_pred: list[int]) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": round(accuracy_score(y_true, y_pred), 3),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 3),
        "recall": round(tp / (tp + fn), 3) if tp + fn else None,
        "false_alarm_rate": round(fp / (fp + tn), 3) if fp + tn else None,
    }


async def run(path: Path, concurrency: int = 4, learn: bool = True, progress=None) -> dict:
    rows = load_csv(path)
    gate = asyncio.Semaphore(concurrency)

    async def one(row: dict) -> pipeline.Decision:
        async with gate:
            decision = await pipeline.decide(row["url"])
        if progress:
            progress(row, decision)
        return decision

    decisions = await asyncio.gather(*(one(row) for row in rows))
    y = [row["label"] for row in rows]
    majority = [int(sum(s >= 0.5 for s in models.scores(r["url"]).values()) >= 2) for r in rows]
    full = [int(d.action == "block") for d in decisions]
    agent_rows = [(r, d) for r, d in zip(rows, decisions, strict=True) if d.verdict]
    if learn:  # long-term memory keeps only confirmed-correct agent sessions
        for row, d in agent_rows:
            if (d.verdict.verdict == "ssrf") == bool(row["label"]):
                memory.add(row["url"], d.verdict.verdict, d.verdict.technique_id, d.verdict.reason)
    report = {
        "dataset": str(path),
        "rows": len(rows),
        "attacks": sum(y),
        "model": settings.model_label,
        "methods": {
            "Majority vote (3 models)": metrics(y, majority),
            "Full pipeline (rules + agent + egress)": metrics(y, full),
        },
        "agent_only": metrics(
            [r["label"] for r, _ in agent_rows],
            [int(d.verdict.verdict == "ssrf") for _, d in agent_rows],
        )
        if agent_rows
        else None,
        "decided_by": dict(Counter(f"{d.stage}:{d.action}" for d in decisions)),
        "agent_errors": sum("agent failed" in d.reason for d in decisions),
        "missed": [
            d.url for d, label in zip(decisions, y, strict=True) if label and d.action == "allow"
        ],
        "false_alarms": [
            d.url
            for d, label in zip(decisions, y, strict=True)
            if not label and d.action == "block"
        ],
        "results": [
            {
                "url": d.url,
                "label": label,
                "action": d.action,
                "stage": d.stage,
                "technique": d.verdict.technique_id if d.verdict else None,
                "reason": d.reason,
            }
            for d, label in zip(decisions, y, strict=True)
        ],
    }
    out = settings.artifacts_dir / f"eval_{path.stem}.json"
    out.write_text(json.dumps(report, indent=2))
    report["output"] = str(out)
    return report
