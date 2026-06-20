"""Database queries for users and roles."""

from __future__ import annotations

from typing import Any, Optional

from pyfarm.storage import StorageBackend

from .models import Role, UserCreate, UserResponse
from .security import hash_password, verify_password


class UserQueries:
    """User database operations."""

    def __init__(self, storage: StorageBackend):
        """Initialize with storage backend."""
        self.storage = storage
        self.users: dict[int, dict[str, Any]] = {}  # In-memory store for Phase 1
        self.user_id_counter = 1

    async def create_user(
        self,
        user_create: UserCreate,
        roles: list[str] | None = None,
    ) -> UserResponse:
        """Create a new user.

        Raises:
            ValueError: If user already exists.
        """
        # Check if user exists
        if await self.get_user_by_username(user_create.username):
            raise ValueError(f"User '{user_create.username}' already exists")

        user_id = self.user_id_counter
        self.user_id_counter += 1

        hashed_password = hash_password(user_create.password)
        now = self._get_now()

        user_data = {
            "id": user_id,
            "username": user_create.username,
            "email": user_create.email,
            "full_name": user_create.full_name,
            "hashed_password": hashed_password,
            "roles": roles or ["observer"],
            "is_active": True,
            "created_at": now,
            "updated_at": now,
        }

        self.users[user_id] = user_data
        return self._to_response(user_data)

    async def get_user_by_id(self, user_id: int) -> Optional[UserResponse]:
        """Get a user by ID."""
        user_data = self.users.get(user_id)
        if user_data:
            return self._to_response(user_data)
        return None

    async def get_user_by_username(self, username: str) -> Optional[UserResponse]:
        """Get a user by username."""
        for user_data in self.users.values():
            if user_data["username"] == username:
                return self._to_response(user_data)
        return None

    async def get_user_by_email(self, email: str) -> Optional[UserResponse]:
        """Get a user by email."""
        for user_data in self.users.values():
            if user_data["email"] == email:
                return self._to_response(user_data)
        return None

    async def verify_password(self, username: str, password: str) -> Optional[UserResponse]:
        """Verify user password. Returns user if valid, None otherwise."""
        for user_data in self.users.values():
            if user_data["username"] == username:
                if not user_data["is_active"]:
                    return None
                if verify_password(password, user_data["hashed_password"]):
                    return self._to_response(user_data)
        return None

    async def list_users(self, skip: int = 0, limit: int = 100) -> list[UserResponse]:
        """List all users with pagination."""
        users_list = list(self.users.values())
        return [
            self._to_response(u) for u in users_list[skip : skip + limit]
        ]

    async def update_user_roles(self, user_id: int, roles: list[str]) -> Optional[UserResponse]:
        """Update user roles."""
        user_data = self.users.get(user_id)
        if not user_data:
            return None

        user_data["roles"] = roles
        user_data["updated_at"] = self._get_now()
        return self._to_response(user_data)

    async def deactivate_user(self, user_id: int) -> Optional[UserResponse]:
        """Deactivate a user."""
        user_data = self.users.get(user_id)
        if not user_data:
            return None

        user_data["is_active"] = False
        user_data["updated_at"] = self._get_now()
        return self._to_response(user_data)

    @staticmethod
    def _to_response(user_data: dict[str, Any]) -> UserResponse:
        """Convert user data to response model."""
        return UserResponse(
            id=user_data["id"],
            username=user_data["username"],
            email=user_data["email"],
            full_name=user_data["full_name"],
            roles=user_data["roles"],
            is_active=user_data["is_active"],
            created_at=user_data["created_at"],
            updated_at=user_data["updated_at"],
        )

    @staticmethod
    def _get_now():
        """Get current UTC datetime."""
        from datetime import datetime, timezone

        return datetime.now(timezone.utc)


class RoleQueries:
    """Role database operations."""

    def __init__(self):
        """Initialize with default roles."""
        self.roles: dict[str, dict[str, Any]] = {}
        self._init_default_roles()

    def _init_default_roles(self) -> None:
        """Initialize default RBAC roles."""
        self.roles["admin"] = {
            "name": "admin",
            "description": "Full system access",
            "permissions": [
                "manage_users",
                "manage_roles",
                "control_grow",
                "override_actuators",
                "view_analytics",
                "configure_system",
            ],
        }
        self.roles["operator"] = {
            "name": "operator",
            "description": "Grow operation and logging",
            "permissions": [
                "control_grow",
                "override_actuators",
                "log_harvest",
                "view_analytics",
            ],
        }
        self.roles["observer"] = {
            "name": "observer",
            "description": "Read-only access to dashboards",
            "permissions": ["view_analytics"],
        }

    async def get_role(self, name: str) -> Optional[dict[str, Any]]:
        """Get role by name."""
        return self.roles.get(name)

    async def list_roles(self) -> list[dict[str, Any]]:
        """List all roles."""
        return list(self.roles.values())

    async def has_permission(self, roles: list[str], permission: str) -> bool:
        """Check if any of the given roles has the permission."""
        for role_name in roles:
            role = await self.get_role(role_name)
            if role and permission in role.get("permissions", []):
                return True
        return False
