"""Authentication endpoints: token issue + user registration."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.api.auth import create_access_token, hash_password, role_satisfies, verify_password
from aegis.api.deps import get_current_user, get_current_user_optional, get_db
from aegis.api.schemas import TokenResponse, UserCreate, UserOut
from aegis.core.enums import Role
from aegis.db.models import User
from aegis.db.persistence import append_audit

router = APIRouter(prefix="/v1/auth", tags=["auth"])


@router.post("/token", response_model=TokenResponse)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.execute(
        select(User).where(User.username == form.username)
    ).scalar_one_or_none()
    if user is None or not verify_password(form.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password"
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User disabled")
    role = user.role if isinstance(user.role, Role) else Role(user.role)
    token = create_access_token(user_id=str(user.id), username=user.username, role=role)
    append_audit(db, actor=user.username, action="login")
    db.commit()
    return TokenResponse(access_token=token, role=role)


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(
    payload: UserCreate,
    db: Session = Depends(get_db),
    caller: User | None = Depends(get_current_user_optional),
):
    """Create a user.

    Bootstrap rule: when no users exist the first account is created as ``admin`` (so a
    fresh deployment is usable). Thereafter registration requires an admin token."""
    user_count = db.execute(select(func.count(User.id))).scalar_one()
    is_bootstrap = user_count == 0

    if not is_bootstrap:
        caller_role = (
            (caller.role if isinstance(caller.role, Role) else Role(caller.role))
            if caller else None
        )
        if caller_role is None or not role_satisfies(caller_role, Role.ADMIN):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="registration is admin-only after bootstrap",
            )

    if db.execute(select(User).where(User.username == payload.username)).scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="username taken")

    role = Role.ADMIN if is_bootstrap else payload.role
    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=role,
    )
    db.add(user)
    db.flush()
    append_audit(db, actor=payload.username, action="user_registered",
                 detail={"role": role.value, "bootstrap": is_bootstrap})
    db.commit()
    db.refresh(user)
    return user


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user
