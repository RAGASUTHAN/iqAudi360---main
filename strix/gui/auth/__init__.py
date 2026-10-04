"""iqAudi360 Authentication, Multi-Tenancy & RBAC Module."""

from __future__ import annotations

from flask import Flask

from strix.gui.auth.db import init_db
from strix.gui.auth.decorators import (
    require_auth,
    require_permission,
    require_role,
    require_tenant_scan_access,
    setup_request_context,
)
from strix.gui.auth.firebase import init_firebase_admin
from strix.gui.auth.rbac import (
    ROLE_ADMIN,
    ROLE_CLIENT,
    ROLE_DEV,
    ROLE_SUPERADMIN,
)
from strix.gui.auth.routes import auth_bp


def init_auth(app: Flask) -> None:
    """Initialize Firebase Admin SDK, SQLite DB, and register auth blueprint & context processor."""
    init_firebase_admin()
    init_db()

    # Register request hook
    app.before_request(setup_request_context)

    # Register blueprint
    app.register_blueprint(auth_bp)

    # Provide context variables to all Jinja templates
    @app.context_processor
    def inject_auth_context():
        from flask import g
        return {
            "current_user": g.get("user"),
            "current_tenant": g.get("current_tenant"),
            "current_role": g.get("current_role"),
            "is_superadmin": g.get("is_superadmin", False),
            "user_tenants": g.get("user_tenants", []),
            "ROLE_SUPERADMIN": ROLE_SUPERADMIN,
            "ROLE_ADMIN": ROLE_ADMIN,
            "ROLE_DEV": ROLE_DEV,
            "ROLE_CLIENT": ROLE_CLIENT,
        }


__all__ = [
    "init_auth",
    "auth_bp",
    "require_auth",
    "require_role",
    "require_permission",
    "require_tenant_scan_access",
    "ROLE_SUPERADMIN",
    "ROLE_ADMIN",
    "ROLE_DEV",
    "ROLE_CLIENT",
]
