"""pyfarm-auth: Identity and authentication service for pyfarm ecosystem.

Provides:
- User registration and login (JWT tokens)
- Role-based access control (admin, operator, observer)
- Token validation for other services
- API key management (future)
- Device certificates (future)
"""

from pyfarm.auth.app import create_app
from pyfarm.auth.models import Role, TokenResponse, UserCreate, UserResponse
from pyfarm.auth.security import create_access_token, decode_access_token

__version__ = "0.1.0"

__all__ = [
    "create_app",
    "Role",
    "UserCreate",
    "UserResponse",
    "TokenResponse",
    "create_access_token",
    "decode_access_token",
]
