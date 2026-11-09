from __future__ import annotations
from dataclasses import dataclass, field, asdict


@dataclass
class Signal:
    id: str
    title: str
    detail: str
    weight: float            # 0..1 contribution to scam likelihood
    critical: bool = False   # critical signals force a high verdict
    category: str = "general"
    evidence: str = ""       # the text that triggered it


@dataclass
class Report:
    score: int
    verdict: str
    verdict_label: str
    scam_type: str
    summary: str
    signals: list[Signal] = field(default_factory=list)
    heuristic_score: int = 0
    llm_score: int | None = None
    llm_used: bool = False
    llm_error: str | None = None
    safe_signs: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    extracted_text: str = ""
    flagged_urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
