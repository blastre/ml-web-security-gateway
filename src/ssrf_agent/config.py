"""Runtime settings. Override any field with an `SSRF_AGENT_<FIELD>` env var or `.env`."""

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

DATA = Path(__file__).resolve().parents[2] / "data"
MODEL_NAMES = {"claude-sonnet-5-5": "Sonnet 5.5", "claude-opus-5-5": "Opus 5.5"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SSRF_AGENT_", env_file=".env", extra="ignore")

    model: str = "claude-sonnet-5-5"
    effort: Literal["low", "medium", "high", "max"] = "low"
    sensitivity: Literal["aggressive", "balanced", "conservative"] = "balanced"
    max_turns: int = 12
    # Fast-rule thresholds on the classifiers' SSRF probability.
    block_above: float = 0.95
    allow_below: float = 0.2
    # Long-term memory retrieval (IDS-Agent Eq. 1).
    memory_k: int = 5
    lambda_recency: float = 0.3
    lambda_similarity: float = 0.7
    data_dir: Path = DATA
    artifacts_dir: Path = Path("artifacts")

    @property
    def model_label(self) -> str:
        return MODEL_NAMES.get(self.model, self.model)


settings = Settings()
