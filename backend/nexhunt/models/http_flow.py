import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, Integer, Float, Boolean, DateTime, LargeBinary, Index
from sqlalchemy.orm import Mapped, mapped_column
from nexhunt.database import Base


class HttpFlow(Base):
    __tablename__ = "http_flows"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), nullable=True)
    request_method: Mapped[str] = mapped_column(String(10), nullable=False)
    request_url: Mapped[str] = mapped_column(Text, nullable=False)
    request_host: Mapped[str] = mapped_column(String(512), nullable=False)
    request_port: Mapped[int] = mapped_column(Integer, default=443)
    request_path: Mapped[str] = mapped_column(Text, default="/")
    request_headers: Mapped[str] = mapped_column(Text, default="{}")  # JSON
    request_body: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    response_status: Mapped[int] = mapped_column(Integer, default=0)
    response_headers: Mapped[str] = mapped_column(Text, default="{}")  # JSON
    response_body: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    response_length: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    is_intercepted: Mapped[bool] = mapped_column(Boolean, default=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    tags: Mapped[str] = mapped_column(Text, default="[]")  # JSON array

    __table_args__ = (
        Index("idx_flows_host", "request_host"),
        Index("idx_flows_status", "response_status"),
        Index("idx_flows_timestamp", "timestamp"),
        Index("idx_flows_project", "project_id"),
    )
