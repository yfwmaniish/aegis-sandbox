"""SQLAlchemy engine, session factory and declarative base.

The engine URL comes from :class:`aegis.core.config.Settings`, so the same models run
on PostgreSQL (deployment) and SQLite (local/test). Engine and sessionmaker are built
lazily and cached so importing the models never forces a DB connection.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from aegis.core.config import get_settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


@lru_cache
def get_engine(url: str | None = None) -> Engine:
    settings = get_settings()
    db_url = url or settings.sqlalchemy_url
    connect_args: dict[str, object] = {}
    if db_url.startswith("sqlite"):
        # Allow use across threads (the inline pipeline runs detonations in a daemon
        # thread) and wait on locks instead of erroring when the worker thread writes
        # state transitions while a request polls the same DB.
        connect_args["check_same_thread"] = False
        connect_args["timeout"] = 30.0
    return create_engine(db_url, pool_pre_ping=True, future=True, connect_args=connect_args)


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional session context: commits on success, rolls back on error."""
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
