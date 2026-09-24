"""Request/sample schema shared by the dataset, the feature pipeline and inference.

``RequestRecord`` is the single input type the detector understands.  Phase 2's
gateway will build one per inbound request; Phase 1's generator builds them
synthetically and attaches a label.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any, Mapping

#: Column order used by the dataset CSV.
DATASET_COLUMNS = (
    "id",
    "label",
    "family",
    "method",
    "url",
    "body",
    "redirect_location",
    "redirect_hops",
    "notes",
)


@dataclass
class RequestRecord:
    """One HTTP request as seen by the gateway.

    Attributes:
        url: The user-supplied URL the application would fetch.
        method: HTTP method of the inbound request.
        body: Request body, when the URL arrives in a POST/PUT payload.
        redirect_location: ``Location`` value observed for this destination,
            i.e. where following the redirect would actually land.  Empty when
            the destination does not redirect.
        redirect_hops: Number of redirects observed before the final response.
    """

    url: str
    method: str = "GET"
    body: str = ""
    redirect_location: str = ""
    redirect_hops: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> "RequestRecord":
        """Build a record from a dict/CSV row, ignoring unrelated keys."""
        known = {f.name for f in fields(cls)}
        payload: dict[str, Any] = {}
        for key in known:
            if key not in mapping:
                continue
            value = mapping[key]
            if value is None:
                continue
            # pandas turns empty CSV cells into NaN; treat them as defaults.
            if isinstance(value, float) and value != value:
                continue
            payload[key] = value
        payload["url"] = str(payload.get("url", ""))
        payload["method"] = str(payload.get("method", "GET")).upper() or "GET"
        payload["body"] = str(payload.get("body", ""))
        payload["redirect_location"] = str(payload.get("redirect_location", ""))
        payload["redirect_hops"] = int(payload.get("redirect_hops", 0) or 0)
        return cls(**payload)


@dataclass
class DatasetSample:
    """A labelled :class:`RequestRecord` plus provenance for the report."""

    id: str
    label: str
    family: str
    record: RequestRecord
    notes: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    def to_row(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "family": self.family,
            "method": self.record.method,
            "url": self.record.url,
            "body": self.record.body,
            "redirect_location": self.record.redirect_location,
            "redirect_hops": self.record.redirect_hops,
            "notes": self.notes,
        }


def coerce_record(value: Any) -> RequestRecord:
    """Accept a record, mapping or bare URL string and return a RequestRecord."""
    if isinstance(value, RequestRecord):
        return value
    if isinstance(value, Mapping):
        return RequestRecord.from_mapping(value)
    if isinstance(value, str):
        return RequestRecord(url=value)
    raise TypeError(f"cannot interpret {type(value)!r} as a RequestRecord")
