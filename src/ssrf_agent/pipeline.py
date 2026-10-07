"""The approved flowchart:

URL -> fast rules --obvious--> allow / block
          '- uncertain -> agent -> allow / block + reason
egress guard (always on) re-checks every allowed URL; nothing overrides it.
"""

from dataclasses import dataclass, field
from typing import Literal

from ssrf_agent import agent, models, rules
from ssrf_agent.config import settings

Stage = Literal["fast_rules", "agent", "egress"]


@dataclass
class Decision:
    url: str
    action: Literal["allow", "block"]
    stage: Stage  # which stage made the final call
    reason: str
    scores: dict[str, float] = field(default_factory=dict)
    verdict: agent.Verdict | None = None
    path: list[str] = field(default_factory=list)  # stages the request passed through


def fast_rules(url: str) -> tuple[Literal["allow", "block", "uncertain"], str, dict]:
    if reason := rules.inbound_block(url):
        return "block", reason, {}
    scores = models.scores(url)
    lr, rf = scores["logistic_regression"], scores["random_forest"]
    if lr >= settings.block_above and rf >= settings.block_above:
        return "block", f"classifiers agree on SSRF (LR {lr}, RF {rf})", scores
    if lr < settings.allow_below and rf < settings.allow_below and not rules.hints(url):
        return "allow", f"classifiers agree on benign (LR {lr}, RF {rf})", scores
    return "uncertain", "classifiers disagree or score is medium", scores


async def decide(url: str, on_event: agent.Event | None = None) -> Decision:
    emit = on_event or (lambda kind, data: None)
    route, reason, scores = fast_rules(url)
    emit("stage", ("fast_rules", route, reason))
    decision = Decision(url, "allow", "fast_rules", reason, scores, path=["fast_rules"])
    if route == "block":
        decision.action = "block"
        return decision
    if route == "uncertain":
        decision.path.append("agent")
        decision.stage = "agent"
        try:
            verdict = await agent.analyse(url, on_event)
            decision.verdict = verdict
            decision.reason = verdict.reason
            if verdict.verdict == "ssrf":
                decision.action = "block"
        except Exception as exc:  # fail closed
            decision.action, decision.reason = "block", f"agent failed ({exc}); blocked"
        emit("stage", ("agent", decision.action, decision.reason))
        if decision.action == "block":
            return decision
    decision.path.append("egress")
    if egress := rules.egress_block(url):
        decision.action, decision.stage, decision.reason = "block", "egress", egress
    emit("stage", ("egress", decision.action, egress or "destination is public"))
    return decision
