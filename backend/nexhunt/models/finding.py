import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column
from nexhunt.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    scan_job_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)  # critical, high, medium, low, info
    vuln_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    parameter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool: Mapped[str | None] = mapped_column(String(50), nullable=True)
    template_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="new")  # new, confirmed, reported, duplicate, false_positive
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_project", "project_id"),
        Index("idx_findings_status", "status"),
    )
