import asyncio
import tomllib

import pytest

from ssrf_agent import agent, models, pipeline, rules
from ssrf_agent.config import settings


@pytest.fixture(scope="session", autouse=True)
def trained(tmp_path_factory):
    settings.artifacts_dir = tmp_path_factory.mktemp("artifacts")
    models.train()


def catalogue():
    with (settings.data_dir / "attacks.toml").open("rb") as handle:
        return tomllib.load(handle)["attacks"]


@pytest.mark.parametrize("attack", catalogue(), ids=lambda a: a["id"])
def test_egress_blocks_every_catalogue_attack(attack):
    assert rules.egress_block(attack["payload"])


@pytest.mark.parametrize(
    ("host", "ip"),
    [
        ("0xa9fea9fe", "169.254.169.254"),
        ("2852039166", "169.254.169.254"),
        ("0251.0376.0251.0376", "169.254.169.254"),
        ("127.1", "127.0.0.1"),
        ("[::ffff:a9fe:a9fe]", "169.254.169.254"),
        ("%31%36%39.254.169.254", "169.254.169.254"),
    ],
)
def test_ip_notations_are_canonicalised(host, ip):
    assert str(rules.parse_ip(host)) == ip


def test_unicode_lookalike_host_is_normalised():
    url = "http://[::ⓕⓕⓕⓕ:①⑥⑨。②⑤④。⑯⑨。②⑤④]:80/"
    assert rules.normalise(url) == "http://[::ffff:169.254.169.254]:80/"
    assert "metadata" in rules.egress_block(url)
    assert "A32" in {h["technique_id"] for h in rules.hints(url)}


def test_public_destination_passes_egress():
    assert rules.egress_block("https://www.example.com/a") is None
    assert rules.egress_block("http://redirect.attacker.lab/r?to=http://public.lab/ok") is None


def run(url, monkeypatch, verdict=None, fail=False):
    async def fake(url, on_event=None):
        if fail:
            raise RuntimeError("boom")
        return verdict

    monkeypatch.setattr(agent, "analyse", fake)
    return asyncio.run(pipeline.decide(url))


def test_obvious_cases_skip_the_agent(monkeypatch):
    blocked = run("file:///etc/passwd", monkeypatch, fail=True)
    assert (blocked.action, blocked.stage, blocked.path) == ("block", "fast_rules", ["fast_rules"])
    allowed = run("https://www.example.com/blog", monkeypatch, fail=True)
    assert allowed.action == "allow" and "agent" not in allowed.path


def test_uncertain_goes_to_agent_and_egress_still_applies(monkeypatch):
    benign = agent.Verdict(verdict="benign", technique_id="none", confidence=0.9, reason="ok")
    d = run("http://intranet.attacker.lab/admin", monkeypatch, verdict=benign)
    assert d.path == ["fast_rules", "agent", "egress"]
    assert (d.action, d.stage) == ("block", "egress")  # the agent cannot override egress


def test_agent_failure_fails_closed(monkeypatch):
    d = run("http://localtest.me/admin", monkeypatch, fail=True)
    assert (d.action, d.stage) == ("block", "agent")


def test_unparseable_url_fails_closed(monkeypatch):
    url = "http://[::127.0.0.1]:6379+&@www.example.com#+@www.example.com/"
    d = run(url, monkeypatch, fail=True)
    assert (d.action, d.stage) == ("block", "fast_rules")
    assert "unparseable" in d.reason
