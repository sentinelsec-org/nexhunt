import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, Float, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from nexhunt.database import Base


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), nullable=True)
    tool: Mapped[str] = mapped_column(String(50), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    options: Mapped[str] = mapped_column(Text, default="{}")  # JSON
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued, running, completed, failed, cancelled
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
