import os
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from nexhunt.config import settings


class Base(DeclarativeBase):
    pass


# Default database (for global settings and project index)
_default_db_path = os.path.join(settings.db_dir, "nexhunt.db")
_default_engine = create_async_engine(
    f"sqlite+aiosqlite:///{_default_db_path}",
    echo=False,
    connect_args={"check_same_thread": False},
)
DefaultSession = async_sessionmaker(_default_engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    """Create all tables in the default database."""
    from nexhunt.models import finding, recon_result  # noqa
    async with _default_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Migrate: add new columns to existing tables without dropping data
        for col, default in [
            ("out_of_scope", "'[]'"),
            ("scope_mode", "'strict'"),
        ]:
            try:
                await conn.exec_driver_sql(
                    f"ALTER TABLE projects ADD COLUMN {col} TEXT NOT NULL DEFAULT {default}"
                )
            except Exception:
                pass  # Column already exists
        try:
            await conn.exec_driver_sql(
                "ALTER TABLE recon_results ADD COLUMN project_id VARCHAR(36)"
            )
        except Exception:
            pass  # Column already exists
        # Endpoint results historically stored their project_id in the `target`
        # column (see recon.py _run_endpoint_check) — move it to the real column.
        await conn.exec_driver_sql(
            "UPDATE recon_results SET project_id = target "
            "WHERE type = 'endpoint' AND project_id IS NULL "
            "AND target IS NOT NULL AND target NOT IN ('', 'global')"
        )


async def get_session() -> AsyncSession:
    """Get a database session."""
    async with DefaultSession() as session:
        yield session
