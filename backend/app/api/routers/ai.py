"""Administrator-facing AI-assisted anomaly analysis.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.db.session import get_db
from app.models.user import User
from app.schemas.ai import AnomalyAnalysisRead
from app.services.anomaly_detection import InsufficientDataError, analyze_user, FEATURE_NAMES
from app.services.alerts import create_alert

router = APIRouter(prefix="/api/admin/anomaly", tags=["ai-anomaly"])


@router.post("/users/{user_id}", response_model=AnomalyAnalysisRead)
def analyze_user_behavior(
    user_id: uuid.UUID,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AnomalyAnalysisRead:
    """Analyze user behavior; this advisory result never changes user state."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    try:
        result = analyze_user(db, user.id)
    except InsufficientDataError as exc:
        return AnomalyAnalysisRead(
            user_id=user.id,
            label="INSUFFICIENT_DATA",
            features={name: 0.0 for name in FEATURE_NAMES},
            sample_count=0,
            explanation="AI-assisted anomaly analysis requires more behavioral data.",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI-assisted anomaly analysis is temporarily unavailable",
        ) from exc

    alert_id = None
    if result.label == "ANOMALOUS":
        alert = create_alert(
            db,
            alert_type="behavioral_anomaly",
            severity="medium",
            score=result.score or 0.0,
            explanation=result.explanation,
            user_id=user.id,
            actor_id=admin_user.id,
            details={"label": result.label},
            dedupe={"alert_type": "behavioral_anomaly", "user_id": user.id},
        )
        alert_id = alert.id
    db.commit()
    return AnomalyAnalysisRead(
        user_id=result.user_id,
        label=result.label,
        score=result.score,
        features=result.features,
        sample_count=result.sample_count,
        explanation=result.explanation,
        alert_id=alert_id,
    )
