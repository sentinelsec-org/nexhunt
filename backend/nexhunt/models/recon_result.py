import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column
from nexhunt.database import Base


class ReconResult(Base):
    __tablename__ = "recon_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    type: Mapped[str] = mapped_column(String(30), nullable=False)  # subdomain, live_host, url, port, screenshot
    target: Mapped[str] = mapped_column(Text, nullable=True)
    data: Mapped[str] = mapped_column(Text, nullable=False)  # JSON blob
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_recon_type", "type"),
    )
