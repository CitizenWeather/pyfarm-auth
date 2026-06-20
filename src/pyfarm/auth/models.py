"""Data models for authentication and authorization."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class Role(str, Enum):
    """User role enumeration."""

    ADMIN = "admin"
    OPERATOR = "operator"
    OBSERVER = "observer"


class UserCreate(BaseModel):
    """Request model for user creation."""

    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str = ""


class UserUpdate(BaseModel):
    """Request model for user update."""

    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    password: Optional[str] = Field(None, min_length=8)


class UserResponse(BaseModel):
    """Response model for user data."""

    id: int
    username: str
    email: str
    full_name: str
    roles: list[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    """Request model for user login."""

    username: str
    password: str


class TokenResponse(BaseModel):
    """Response model for token."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user: UserResponse


class TokenPayload(BaseModel):
    """JWT token payload."""

    sub: str  # username
    user_id: int
    roles: list[str]
    exp: int  # expiration timestamp
    iat: int  # issued at timestamp


class RoleCreateRequest(BaseModel):
    """Request model for role creation."""

    name: str = Field(..., min_length=3, max_length=50)
    description: str = ""
    permissions: list[str] = Field(default_factory=list)


class RoleResponse(BaseModel):
    """Response model for role data."""

    name: str
    description: str
    permissions: list[str]


class PermissionResponse(BaseModel):
    """Response model for permission data."""

    name: str
    description: str
