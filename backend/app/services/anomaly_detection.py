"""AI-assisted behavioral anomaly detection using Isolation Forest."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from sklearn.ensemble import IsolationForest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog

FEATURE_NAMES = (
    "login_frequency",
    "failed_login_count",
    "evidence_access_frequency",
    "evidence_access_volume",
    "unusual_access_time",
    "case_access_pattern",
    "transfer_frequency",
)


class InsufficientDataError(ValueError):
    """Raised when there are too few behavioral samples to train a model."""


@dataclass(frozen=True)
class AnomalyResult:
    user_id: UUID
    label: str
    score: float | None
    features: dict[str, float]
    sample_count: int
    explanation: str


def _event_actor_id(event: AuditLog) -> UUID | None:
    return event.actor_id


def build_user_features(db: Session) -> dict[UUID, dict[str, float]]:
    """Aggregate safe audit metadata into behavioral features per actor."""
    events = db.scalars(select(AuditLog).order_by(AuditLog.created_at, AuditLog.id)).all()
    features: dict[UUID, dict[str, float]] = defaultdict(lambda: {name: 0.0 for name in FEATURE_NAMES})
    for event in events:
        actor_id = _event_actor_id(event)
        if actor_id is None:
            continue
        values = features[actor_id]
        values["login_frequency"] += float(event.action == "LOGIN")
        values["failed_login_count"] += float(event.action == "LOGIN_FAILURE")
        values["evidence_access_frequency"] += float(event.action == "EVIDENCE_ACCESSED")
        if event.action == "EVIDENCE_ACCESSED" and event.details:
            values["evidence_access_volume"] += float(event.details.get("file_size", 0) or 0)
        if event.action in {"EVIDENCE_ACCESSED", "INTEGRITY_CHECK"} and event.created_at:
            hour = event.created_at.astimezone(timezone.utc).hour
            values["unusual_access_time"] += float(hour < 5 or hour >= 23)
        values["case_access_pattern"] += float(event.resource_type == "case")
        values["transfer_frequency"] += float(event.action == "CUSTODY_TRANSFER")
    return dict(features)


def analyze_user(db: Session, user_id: UUID) -> AnomalyResult:
    """Analyze one user against the behavioral population, advisory only."""
    features_by_user = build_user_features(db)
    if user_id not in features_by_user:
        raise InsufficientDataError("The target user has no behavioral audit activity")
    if len(features_by_user) < 2:
        raise InsufficientDataError("At least two users with audit activity are required")

    user_ids = sorted(features_by_user, key=str)
    matrix = [[features_by_user[uid][name] for name in FEATURE_NAMES] for uid in user_ids]
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    model.fit(matrix)
    index = user_ids.index(user_id)
    prediction = int(model.predict([matrix[index]])[0])
    decision_score = float(model.decision_function([matrix[index]])[0])
    label = "NORMAL" if prediction == 1 else "ANOMALOUS"
    explanation = (
        "AI-assisted anomaly analysis found behavior consistent with the observed population."
        if label == "NORMAL"
        else "AI-assisted anomaly analysis found behavior that differs from the observed population."
    )
    return AnomalyResult(user_id, label, decision_score, features_by_user[user_id], len(user_ids), explanation)
