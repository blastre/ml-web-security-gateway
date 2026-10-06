"""The SSRF agent's toolbox (IDS-Agent Sec. 3.2 action space).

Every tool acts on the *session's* request only; the model chooses which tools to run and
with which settings, never which host to resolve. Tools return JSON-serialisable
observations. DNS lookups resolve names; no tool opens a connection to the destination.
"""

import csv
import itertools
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import unquote, urlsplit

import httpx

from mlwsg import knowledge, rules
from mlwsg.catalogue import load
from mlwsg.egress import LAB_ADDRESSES
from mlwsg.memory import LongTermMemory
from mlwsg.models import CLASSIFIERS, FEATURE_NAMES, classify, url_features

Resolver = Callable[[str], list[str]]


def system_resolver(host: str) -> list[str]:
    """One getaddrinfo lookup; failures are an empty answer, never an exception."""
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return []
    return list(dict.fromkeys(answer[4][0] for answer in answers))


class LabResolver:
    """Deterministic DNS for the lab zone, mirroring `compose.yaml` and the catalogue.

    ``rebind.attacker.lab`` alternates public then metadata answers (A18), and
    ``<ip>.nip.io`` answers with the embedded IP, as the real wildcard service does.
    """

    _PUBLIC_EXAMPLE = "93.184.216.34"

    def __init__(self) -> None:
        self.zone: dict[str, list[list[str]]] = {
            host: [[str(address) for address in addresses]]
            for host, addresses in LAB_ADDRESSES.items()
        }
        for attack in load().attacks:
            host = urlsplit(attack.payload).hostname or ""
            if attack.vector == "dns" and attack.resolves_to is not None:
                self.zone[host] = [[str(attack.resolves_to)]]
        self.zone["rebind.attacker.lab"] = [["10.20.0.20"], [str(ip_address("169.254.169.254"))]]
        self.zone["localtest.me"] = [["127.0.0.1"]]
        self._turns: dict[str, itertools.cycle] = {}

    def __call__(self, host: str) -> list[str]:
        host = host.lower().rstrip(".")
        if host in self.zone:
            turns = self._turns.setdefault(host, itertools.cycle(self.zone[host]))
            return list(next(turns))
        if host.endswith(".localtest.me"):
            return ["127.0.0.1"]
        wildcard = re.fullmatch(
            r"(?:[a-z0-9-]+\.)*?((?:\d{1,3}\.){3}\d{1,3})\.(?:nip|sslip)\.io", host
        )
        if wildcard:
            return [wildcard.group(1)]
        if re.fullmatch(r"(?:[a-z0-9-]+\.)+example\.(?:com|org|net)", host) or host in (
            "example.com",
            "example.org",
            "example.net",
        ):
            return [self._PUBLIC_EXAMPLE]
        return []


class RemoteResolver:
    """Ask `vuln-app`'s DNS-only `/resolve` endpoint; the gateway has no lab DNS itself."""

    def __init__(self, app_url: str, timeout: float = 3.0) -> None:
        self.app_url, self.timeout = app_url, timeout

    def __call__(self, host: str) -> list[str]:
        try:
            response = httpx.get(
                f"{self.app_url}/resolve",
                params={"host": host},
                timeout=self.timeout,
                trust_env=False,
            )
            response.raise_for_status()
            answers = response.json().get("answers", [])
        except (httpx.HTTPError, ValueError):
            return []
        return [str(answer) for answer in answers][:16]


_NO_INPUT = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
_LAB_PUBLIC_ADDRESSES = {address for values in LAB_ADDRESSES.values() for address in values}


def classify_address(address: str) -> dict:
    """Name the protected asset an address belongs to, if any."""
    ip = ip_address(address.split("%")[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip in _LAB_PUBLIC_ADDRESSES:
        return {"address": str(ip), "public": True, "asset": "public-lab-fixture"}
    asset = next((a.name for a in load().assets.values() if a.contains(ip)), None)
    if asset is None and ip in rules.METADATA_ADDRESSES:
        asset = "metadata"
    if asset is None and not ip.is_global:
        asset = "non-public"
    return {"address": str(ip), "public": asset is None, "asset": asset or "public"}


@dataclass
class Toolbox:
    """Tools bound to one request. Memory, knowledge and destination can be ablated."""

    url: str
    model_path: str | Path
    resolver: Resolver = system_resolver
    memory: LongTermMemory | None = None
    use_knowledge: bool = True
    use_destination: bool = True
    observations: list[str] = field(default_factory=list)

    SPECS = (
        {
            "name": "extract_request",
            "description": "Data extraction: parse the request URL under inspection into "
            "scheme, host, port, path, query keys and fragment.",
            "input_schema": _NO_INPUT,
        },
        {
            "name": "preprocess",
            "description": "Preprocessing: the lexical feature vector the ML classifiers "
            "see (host shape, encodings, lengths). Never includes the address itself.",
            "input_schema": _NO_INPUT,
        },
        {
            "name": "classify",
            "description": "Classification: run one pretrained classifier and return its "
            "top-3 labels with confidences. logistic_regression, random_forest and "
            "isolation_forest (anomaly detector trained on benign URLs) return ssrf/benign; "
            "technique_forest returns catalogue technique IDs (A01-A22) or benign, but it "
            "only knows techniques seen in training.",
            "input_schema": {
                "type": "object",
                "properties": {"model": {"type": "string", "enum": list(CLASSIFIERS)}},
                "required": ["model"],
                "additionalProperties": False,
            },
        },
        {
            "name": "url_rules",
            "description": "Deterministic rules: the strict inbound policy decision plus "
            "which catalogue techniques the URL's shape matches (IP encodings, userinfo, "
            "backslash, schemes, embedded redirect URLs).",
            "input_schema": _NO_INPUT,
        },
        {
            "name": "resolve_destination",
            "description": "Where the request really goes: canonical address of IP "
            "literals, two DNS lookups for names (to detect rebinding), the protected asset "
            "each address belongs to, and the same analysis for URLs embedded in query "
            "parameters (open-redirect targets). DNS only; nothing is fetched.",
            "input_schema": _NO_INPUT,
        },
        {
            "name": "knowledge_retrieval",
            "description": "Search the SSRF knowledge base (22 catalogue techniques and "
            "OWASP SSRF guidance) and return the 3 most relevant passages.",
            "input_schema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": False,
            },
        },
        {
            "name": "memory_retrieval",
            "description": "Long-term memory: the 5 most similar and recent past sessions "
            "with confirmed-correct verdicts, as demonstrations.",
            "input_schema": _NO_INPUT,
        },
    )

    def specs(self) -> list[dict]:
        drop = set()
        if not self.use_knowledge:
            drop.add("knowledge_retrieval")
        if self.memory is None:
            drop.add("memory_retrieval")
        if not self.use_destination:
            drop.add("resolve_destination")
        return [dict(spec, strict=True) for spec in self.SPECS if spec["name"] not in drop]

    def run(self, name: str, arguments: dict) -> dict:
        """Execute one action; failures are observations, so the agent can recover."""
        handler = getattr(self, f"_{name}", None)
        if name not in {spec["name"] for spec in self.specs()} or handler is None:
            observation = {"error": f"unknown or disabled tool: {name}"}
        else:
            try:
                observation = handler(**arguments)
            except (TypeError, ValueError, OSError) as exc:
                observation = {"error": str(exc)[:300]}
        self.observations.append(f"{name}: {observation}")
        return observation

    # --- tools -------------------------------------------------------------------------

    def _extract_request(self) -> dict:
        try:
            parts = urlsplit(self.url)
            port = parts.port
        except ValueError as exc:
            return {"url": self.url, "parse_error": str(exc)}
        return {
            "url": self.url,
            "scheme": parts.scheme,
            "host": parts.hostname,
            "port": port,
            "userinfo": "@" in parts.netloc,
            "path": parts.path,
            "query_keys": [pair.split("=")[0] for pair in parts.query.split("&") if pair],
            "fragment": bool(parts.fragment),
            "length": len(self.url),
        }

    def _preprocess(self) -> dict:
        try:
            values = url_features(self.url)
        except ValueError as exc:
            return {"error": f"cannot featurise: {exc}"}
        return {name: round(value, 3) for name, value in zip(FEATURE_NAMES, values, strict=True)}

    def _classify(self, model: str) -> dict:
        try:
            ranked = classify(self.url, self.model_path, model)
        except FileNotFoundError:
            return {"error": "model artifact missing; run uv run mlwsg train"}
        return {"model": model, "top_k": [{"label": label, "confidence": p} for label, p in ranked]}

    def _url_rules(self) -> dict:
        hints = rules.technique_hints(self.url)
        return {
            "inbound_policy": rules.inbound_reason(self.url) or "pass",
            "hints": [
                {"technique_id": hint.technique_id or "none", "signal": hint.signal}
                for hint in hints
            ],
        }

    def _destination(self, url: str) -> dict:
        try:
            parts = urlsplit(url)
            host = unquote(parts.hostname or "").strip("[]").rstrip(".").lower()
        except ValueError:
            return {"host": None, "resolved": False, "addresses": []}
        result = {"scheme": parts.scheme, "host": host, "literal": False, "rebinding": False}
        literal = rules.literal_address(host) if host else None
        if literal is not None:
            lookups = [[str(literal)]]
            result["literal"] = True
        elif host:
            lookups = [self.resolver(host), self.resolver(host)]
        else:
            lookups = [[]]
        seen = list(dict.fromkeys(address for lookup in lookups for address in lookup))
        addresses = []
        for address in seen:
            try:
                addresses.append(classify_address(address))
            except ValueError:
                addresses.append({"address": address, "public": False, "asset": "invalid"})
        result["lookups"] = lookups
        result["addresses"] = addresses
        result["resolved"] = bool(addresses)
        result["non_public"] = any(not item["public"] for item in addresses)
        if len(lookups) == 2 and lookups[0] and lookups[1] and set(lookups[0]) != set(lookups[1]):
            result["rebinding"] = True
        return result

    def _resolve_destination(self) -> dict:
        main = self._destination(self.url)
        hints = []
        if not main["literal"] and main["host"] and main["non_public"]:
            if main["rebinding"]:
                hints.append(
                    {"technique_id": "A18", "signal": "answers changed public to internal"}
                )
            elif main["host"] not in rules.METADATA_HOSTS:
                hints.append({"technique_id": "A17", "signal": "hostname resolves internally"})
        alternate = None
        if "\\" in self.url:
            # WHATWG parsers treat "\" as "/" in special schemes; resolve that host as well.
            alternate = self._destination(self.url.replace("\\", "/"))
            if alternate.get("non_public"):
                hints.append(
                    {"technique_id": "A15", "signal": "WHATWG parse reaches internal host"}
                )
        redirects = []
        for target in rules.embedded_urls(self.url):
            hop = self._destination(target)
            redirects.append(hop)
            if hop.get("non_public"):
                downgrade = main.get("scheme") == "https" and hop.get("scheme") == "http"
                assets = {item["asset"] for item in hop["addresses"]}
                if downgrade and "metadata" not in assets:
                    hints.append(
                        {"technique_id": "A20", "signal": "https redirect to internal http"}
                    )
                else:
                    hints.append({"technique_id": "A19", "signal": "redirect target is internal"})
        return {
            "destination": main,
            "alternate_parse": alternate,
            "redirect_targets": redirects,
            "final_destination_non_public": main.get("non_public", False)
            or bool(alternate and alternate.get("non_public"))
            or any(hop.get("non_public") for hop in redirects),
            "hints": hints,
        }

    def _knowledge_retrieval(self, query: str) -> dict:
        hits = knowledge.search(query[:500], k=3)
        return {
            "passages": [
                {
                    "key": doc.key,
                    "title": doc.title,
                    "text": doc.text[:700],
                    "similarity": round(s, 3),
                }
                for doc, s in hits
            ]
        }

    def _memory_retrieval(self) -> dict:
        assert self.memory is not None
        recalled = self.memory.retrieve(" ".join(self.observations[-8:]), k=5)
        return {
            "demonstrations": [
                {
                    "verdict": item.verdict,
                    "technique_id": item.technique_id,
                    "relevance": item.score,
                    "observations": item.observations[:400],
                }
                for item in recalled
            ]
        }


def dataset_line(path: str | Path, line: int) -> dict:
    """Data extraction by line number (1 = first data row), like IDS-Agent's DataLoader."""
    with Path(path).open(newline="", encoding="utf-8") as handle:
        for number, row in enumerate(csv.DictReader(handle), start=1):
            if number == line:
                return row
    raise ValueError(f"dataset has no line {line}")
