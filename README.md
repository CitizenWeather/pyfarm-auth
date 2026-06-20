# pyfarm-auth

Identity and authentication service for the pyfarm ecosystem.

Provides:
- User registration and login (JWT tokens)
- Role-based access control (RBAC): admin, operator, observer
- Token validation for other pyfarm services
- API key management (Phase 2+)
- Device certificates (Phase 3+)

## Quick Start

```python
from pyfarm.auth import create_app

app = create_app()
# Run with: uvicorn pyfarm.auth.app:app --port 8001
```

## Roles

### admin
Full system access: manage users, roles, control, overrides, analytics, config

### operator
Grow operation: control grow, overrides, harvest logging, analytics

### observer
Read-only: analytics dashboards only

## API Endpoints

**Authentication**
- POST /api/v1/auth/register — User registration
- POST /api/v1/auth/login — User login (returns JWT)
- POST /api/v1/auth/verify — Verify token (for pyfarm-api)

**Users**
- GET /api/v1/users/me — Current user info
- GET /api/v1/users — List users (admin)
- PUT /api/v1/users/{id}/roles — Update roles (admin)

**Roles**
- GET /api/v1/roles — List roles

## Configuration

- `AUTH_SECRET_KEY` — JWT signing secret
- `ACCESS_TOKEN_EXPIRE_MINUTES` — Token TTL (default: 1440)
- `PYFARM_STORAGE_BACKEND` — sqlite or postgres

## Testing

```bash
pytest tests/
```
