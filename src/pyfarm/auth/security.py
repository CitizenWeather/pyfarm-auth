"""Security utilities for authentication."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from passlib.context import CryptContext

from pyfarm.config import get_settings

from .models import TokenPayload

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT algorithm
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    username: str,
    user_id: int,
    roles: list[str],
    expires_delta: Optional[timedelta] = None,
) -> tuple[str, datetime]:
    """Create a JWT access token.

    Returns:
        Tuple of (token, expiration_datetime)
    """
    settings = get_settings()

    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.access_token_expire_minutes)

    now = datetime.now(timezone.utc)
    expires = now + expires_delta

    payload = TokenPayload(
        sub=username,
        user_id=user_id,
        roles=roles,
        exp=int(expires.timestamp()),
        iat=int(now.timestamp()),
    )

    encoded_jwt = jwt.encode(
        payload.model_dump(),
        settings.auth_secret_key.get_secret_value(),
        algorithm=ALGORITHM,
    )

    return encoded_jwt, expires


def decode_access_token(token: str) -> Optional[TokenPayload]:
    """Decode and validate a JWT access token.

    Returns:
        TokenPayload if valid, None if invalid or expired.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.auth_secret_key.get_secret_value(),
            algorithms=[ALGORITHM],
        )
        return TokenPayload(**payload)
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception:
        return None
