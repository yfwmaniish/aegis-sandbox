"""FastAPI dependencies: DB session, authenticated user, RBAC guard."""

from __future__ import annotations

import uuid
from collections.abc import Iterator

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from aegis.api.auth import JWTError, decode_token, role_satisfies
from aegis.core.enums import Role
from aegis.db.base import get_sessionmaker
from aegis.db.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v1/auth/token")
# Optional variant: routes that are open during bootstrap but locked down afterwards.
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="/v1/auth/token", auto_error=False)


def get_db() -> Iterator[Session]:
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        claims = decode_token(token)
        user_id = claims.get("sub")
        if not user_id:
            raise cred_exc
    except JWTError as exc:
        raise cred_exc from exc

    user = db.get(User, uuid.UUID(user_id))
    if user is None or not user.is_active:
        raise cred_exc
    return user


def get_current_user_optional(
    token: str | None = Depends(oauth2_scheme_optional), db: Session = Depends(get_db)
) -> User | None:
    """Return the authenticated user, or ``None`` if no/invalid token was supplied."""
    if not token:
        return None
    try:
        claims = decode_token(token)
        user_id = claims.get("sub")
        if not user_id:
            return None
        user = db.get(User, uuid.UUID(user_id))
    except (JWTError, ValueError):
        return None
    return user if (user and user.is_active) else None


def require_role(required: Role):
    """Dependency factory enforcing a minimum role (admin always passes)."""

    def _guard(user: User = Depends(get_current_user)) -> User:
        actual = user.role if isinstance(user.role, Role) else Role(user.role)
        if not role_satisfies(actual, required):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires role '{required.value}'",
            )
        return user

    return _guard
