import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from nexhunt.database import Base


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scope: Mapped[str] = mapped_column(Text, default="[]")        # in-scope patterns JSON
    out_of_scope: Mapped[str] = mapped_column(Text, default="[]") # out-of-scope patterns JSON
    scope_mode: Mapped[str] = mapped_column(String(20), default="strict")  # strict | permissive
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    type: Mapped[str] = mapped_column(String(20), default="domain")  # domain, ip, cidr
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
