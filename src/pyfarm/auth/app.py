"""FastAPI application for authentication service."""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pyfarm.core.storage import get_backend

from .models import (
    LoginRequest,
    Role,
    TokenResponse,
    UserCreate,
    UserResponse,
)
from .queries import RoleQueries, UserQueries
from .security import create_access_token, decode_access_token

# HTTP Bearer security scheme
security = HTTPBearer()


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="pyfarm-auth",
        description="Identity and authentication service for pyfarm",
        version="0.1.0",
    )

    # Initialize services
    storage = get_backend()
    user_queries = UserQueries(storage)
    role_queries = RoleQueries()

    # Dependency to get current user
    async def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ) -> UserResponse:
        """Get authenticated user from JWT token."""
        token = credentials.credentials
        payload = decode_access_token(token)

        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )

        user = await user_queries.get_user_by_id(payload.user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )

        return user

    # Health check
    @app.get("/health")
    async def health() -> dict[str, str]:
        """Health check endpoint."""
        return {"status": "ok"}

    # Authentication Routes
    @app.post("/api/v1/auth/register", response_model=UserResponse)
    async def register(user_create: UserCreate) -> UserResponse:
        """Register a new user."""
        try:
            return await user_queries.create_user(user_create, roles=["observer"])
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            )

    @app.post("/api/v1/auth/login", response_model=TokenResponse)
    async def login(login_request: LoginRequest) -> TokenResponse:
        """Authenticate user and issue JWT token."""
        user = await user_queries.verify_password(
            login_request.username,
            login_request.password,
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )

        token, expires = create_access_token(
            username=user.username,
            user_id=user.id,
            roles=user.roles,
        )

        # Calculate expires_in in seconds
        import time
        expires_in = int(expires.timestamp() - time.time())

        return TokenResponse(
            access_token=token,
            expires_in=expires_in,
            user=user,
        )

    @app.post("/api/v1/auth/verify")
    async def verify_token(
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ) -> dict:
        """Verify JWT token validity (for pyfarm-api)."""
        token = credentials.credentials
        payload = decode_access_token(token)

        if not payload:
            return {"valid": False}

        return {
            "valid": True,
            "user_id": payload.user_id,
            "username": payload.sub,
            "roles": payload.roles,
        }

    # User Routes
    @app.get("/api/v1/users/me", response_model=UserResponse)
    async def get_current_user_info(
        current_user: UserResponse = Depends(get_current_user),
    ) -> UserResponse:
        """Get current authenticated user info."""
        return current_user

    @app.get("/api/v1/users/{user_id}", response_model=UserResponse)
    async def get_user(
        user_id: int,
        current_user: UserResponse = Depends(get_current_user),
    ) -> UserResponse:
        """Get user by ID (admin only)."""
        if "admin" not in current_user.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can view other users",
            )

        user = await user_queries.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        return user

    @app.get("/api/v1/users", response_model=list[UserResponse])
    async def list_users(
        current_user: UserResponse = Depends(get_current_user),
        skip: int = 0,
        limit: int = 100,
    ) -> list[UserResponse]:
        """List all users (admin only)."""
        if "admin" not in current_user.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can list users",
            )

        return await user_queries.list_users(skip=skip, limit=limit)

    @app.put("/api/v1/users/{user_id}/roles")
    async def update_user_roles(
        user_id: int,
        roles: list[str],
        current_user: UserResponse = Depends(get_current_user),
    ) -> UserResponse:
        """Update user roles (admin only)."""
        if "admin" not in current_user.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can update roles",
            )

        # Validate roles
        valid_roles = [r.value for r in Role]
        if not all(r in valid_roles for r in roles):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid roles. Must be one of: {valid_roles}",
            )

        user = await user_queries.update_user_roles(user_id, roles)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        return user

    # Role Routes
    @app.get("/api/v1/roles")
    async def list_roles(
        current_user: UserResponse = Depends(get_current_user),
    ) -> list[dict]:
        """List all available roles."""
        return await role_queries.list_roles()

    return app


if __name__ == "__main__":
    import uvicorn

    app = create_app()
    uvicorn.run(app, host="127.0.0.1", port=8001)
