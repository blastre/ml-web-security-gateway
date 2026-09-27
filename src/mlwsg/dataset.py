"""Offline, synthetic URL examples for the SSRF research lab.

A family is one catalogue technique (or one benign URL pattern). All variants of
that family stay on the same side of the holdout; these examples are not evidence
of performance on independently collected traffic.
"""

import csv
import random
from pathlib import Path
from urllib.parse import urlsplit

from mlwsg.catalogue import load

_FIELDS = ("url", "label", "family", "split")
_BENIGN = {
    "articles": "https://www.example.com/articles/introducing-our-team",
    "catalogue": "https://shop.example.com/products/blue-notebook",
    "documentation": "https://docs.example.org/guides/getting-started",
    "download": "https://downloads.example.net/releases/client.tar.gz",
    "events": "https://events.example.org/calendar/conference",
    "images": "https://cdn.example.net/images/banner.png",
    "news": "http://news.example.com/world/technology",
    "public-api": "https://api.example.org/v2/catalog/items?limit=10",
    "search": "https://search.example.com/?q=weather",
    "support": "https://help.example.net/support/contact",
    "video": "https://media.example.org/watch/tutorial",
    "lab-public": "http://public.lab/ok",
    "lab-redirect": "http://redirect.attacker.lab/r?to=http://public.lab/ok",
    "weather": "https://weather.example.com/forecast/tomorrow",
}


def _variant(url: str, index: int, rng: random.Random) -> str:
    """Vary harmless query/fragment data without rewriting the host or target path."""
    if index == 0:
        return url
    parsed = urlsplit(url)
    suffix = f"{index:x}-{rng.getrandbits(32):08x}"
    # Fragment and scheme case are independent of the requested resource. Query
    # parameters preserve the existing redirect's `to` destination, if any.
    if index % 4 == 0:
        separator = "&" if parsed.query else "?"
        return f"{url}{separator}ref={suffix}"
    if index % 4 == 1:
        return f"{url}#ref-{suffix}"
    if index % 4 == 2:
        separator = "&" if parsed.query else "?"
        return f"{url}{separator}ref={suffix}#view"
    return f"{parsed.scheme.upper()}{url[len(parsed.scheme) :]}#ref-{suffix}"


def generate(output_path: str | Path, n_per_family: int = 20, seed: int = 20240501) -> dict:
    """Write labeled examples without network access; return dataset counts."""
    if n_per_family < 1:
        raise ValueError("n_per_family must be positive")
    rng = random.Random(seed)
    catalogue = load()
    attacks = [(attack.id, attack.payload) for attack in catalogue.attacks]
    benign = [(f"benign:{name}", url) for name, url in _BENIGN.items()]
    if len(attacks) < 2 or len(benign) < 2:
        raise ValueError("a grouped holdout requires at least two families per label")

    # Variants of a technique are one family. Catalogue techniques that reach
    # the same literal destination are also kept together, so the holdout does
    # not see an address already represented by another attack family.
    attack_groups: dict[str, list[str]] = {}
    for attack in catalogue.attacks:
        key = str(attack.resolves_to) if attack.resolves_to is not None else attack.id
        attack_groups.setdefault(key, []).append(attack.id)
    groups = list(attack_groups.values())
    rng.shuffle(groups)
    target_count = max(1, round(len(attacks) * 0.25))
    attack_test = set()
    for group in groups:
        if len(attack_test) + len(group) <= target_count:
            attack_test.update(group)
    if not attack_test:
        attack_test.update(min(groups, key=len))

    benign_names = [
        family for family, _ in benign if family not in ("benign:lab-public", "benign:lab-redirect")
    ]
    rng.shuffle(benign_names)
    test_families = attack_test | set(benign_names[: max(1, round(len(benign) * 0.25))])

    rows = [
        {
            "url": _variant(url, index, rng),
            "label": label,
            "family": family,
            "split": "test" if family in test_families else "train",
        }
        for label, families in ((1, attacks), (0, benign))
        for family, url in families
        for index in range(n_per_family)
    ]
    rng.shuffle(rows)
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return {
        "path": str(destination),
        "rows": len(rows),
        "attack_families": len(attacks),
        "benign_families": len(benign),
        "train_rows": sum(row["split"] == "train" for row in rows),
        "test_rows": sum(row["split"] == "test" for row in rows),
        "seed": seed,
    }
