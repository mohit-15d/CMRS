"""Chain-of-custody PDF report schemas (Stage 19)."""

import uuid

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ReportRead(BaseModel):
    """Metadata about a generated chain-of-custody PDF report.

    The on-disk ``storage_reference`` is deliberately NOT exposed; clients
    download the PDF through the controlled ``download_url`` endpoint.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID
    report_identifier: str
    status: str
    generated_at: datetime
    generated_by: str | None = None
    download_url: str
