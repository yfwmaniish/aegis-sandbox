"""Authentication & RBAC: password hashing, JWT issue/verify, role enforcement.

JWTs are signed with ``AEGIS_JWT_SECRET`` (HS256 by default). Tokens carry the user id
(``sub``), username and role; the role drives RBAC via :func:`require_role`
(FR-14.1 / TRD §7.2). Passwords are bcrypt-hashed (NFR-1, no plaintext secrets).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from aegis.core.config import get_settings
from aegis.core.enums import Role

# pbkdf2_sha256: pure-Python (hashlib), no native lib, no bcrypt 72-byte cap — avoids
# the passlib/bcrypt>=4.1 backend incompatibility while remaining a strong KDF.
_pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def hash_password(plain: str) -> str:
    return _pwd.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd.verify(plain, hashed)


def create_access_token(*, user_id: str, username: str, role: Role) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    claims = {
        "sub": user_id,
        "username": username,
        "role": role.value if isinstance(role, Role) else str(role),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.jwt_ttl_minutes)).timestamp()),
    }
    return jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_alg)


def decode_token(token: str) -> dict[str, Any]:
    """Decode/verify a JWT. Raises :class:`JWTError` on any problem."""
    settings = get_settings()
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_alg])


# Role hierarchy: admin can do everything; others are peers for their own scope.
_ROLE_RANK = {Role.ANALYST: 1, Role.DETECTION_ENGINEER: 1, Role.RESEARCHER: 1, Role.ADMIN: 10}


def role_satisfies(actual: Role, required: Role) -> bool:
    if actual == Role.ADMIN:
        return True
    return actual == required or _ROLE_RANK.get(actual, 0) >= _ROLE_RANK.get(required, 99)


__all__ = [
    "hash_password",
    "verify_password",
    "create_access_token",
    "decode_token",
    "role_satisfies",
    "JWTError",
]
