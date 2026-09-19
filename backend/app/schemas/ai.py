"""AI-assisted anomaly analysis schemas."""

from uuid import UUID

from pydantic import BaseModel, Field


class AnomalyAnalysisRead(BaseModel):
    """Advisory anomaly analysis result; never a legal conclusion."""

    user_id: UUID
    label: str = Field(description="NORMAL, ANOMALOUS, or INSUFFICIENT_DATA")
    score: float | None = None
    features: dict[str, float]
    sample_count: int
    explanation: str
    advisory: bool = True
    alert_id: UUID | None = None
