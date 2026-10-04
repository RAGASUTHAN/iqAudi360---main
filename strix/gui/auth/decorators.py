"""Authentication and authorization middleware decorators for Flask."""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable

from flask import g, jsonify, redirect, render_template, request, session, url_for

from strix.gui.auth.db import (
    get_or_create_user,
    get_scan_ownership,
    get_tenant_by_id,
    get_tenant_membership,
    get_user_by_id,
    list_tenants_for_user,
    log_audit_event,
)
from strix.gui.auth.firebase import verify_id_token
from strix.gui.auth.rbac import ROLE_CLIENT, ROLE_SUPERADMIN, has_permission

logger = logging.getLogger(__name__)


def is_api_request() -> bool:
    """Detect if the current request expects a JSON API response."""
    return (
        request.path.startswith("/api/")
        or request.is_json
        or request.headers.get("Accept", "").find("application/json") != -1
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )


def authenticate_request() -> dict[str, Any] | None:
    """Authenticate request using either session cookie or Bearer Firebase ID token."""
    # 1. Check Authorization Bearer header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        decoded = verify_id_token(token)
        if decoded:
            uid = decoded.get("uid")
            email = decoded.get("email", "")
            name = decoded.get("name") or decoded.get("display_name")
            picture = decoded.get("picture")
            user = get_or_create_user(uid, email, name, picture)
            return user

    # 2. Check Flask Session
    user_id = session.get("user_id")
    if user_id:
        user = get_user_by_id(user_id)
        if user:
            return user

    return None


def setup_request_context() -> None:
    """Load current user, active tenant, and role into Flask's `g` context object."""
    g.user = authenticate_request()
    g.is_superadmin = False
    g.current_tenant = None
    g.current_role = None
    g.user_tenants = []

    if not g.user:
        return

    g.is_superadmin = bool(g.user.get("is_superadmin"))
    all_tenants = list_tenants_for_user(g.user["user_id"], is_superadmin=g.is_superadmin)
    g.user_tenants = all_tenants

    # Determine active tenant
    active_tenant_id = session.get("active_tenant_id")
    current_tenant = None

    if active_tenant_id:
        # Verify user still has access to this tenant
        if g.is_superadmin:
            current_tenant = get_tenant_by_id(active_tenant_id)
        else:
            membership = get_tenant_membership(active_tenant_id, g.user["user_id"])
            if membership and membership.get("status") == "active":
                current_tenant = get_tenant_by_id(active_tenant_id)

    # Fallback to first accessible tenant
    if not current_tenant and all_tenants:
        current_tenant = all_tenants[0]
        session["active_tenant_id"] = current_tenant["tenant_id"]

    g.current_tenant = current_tenant

    # Determine current role
    if g.is_superadmin:
        g.current_role = ROLE_SUPERADMIN
    elif g.current_tenant:
        membership = get_tenant_membership(g.current_tenant["tenant_id"], g.user["user_id"])
        g.current_role = membership["role"] if membership else ROLE_CLIENT
    else:
        g.current_role = ROLE_CLIENT


def require_auth(view_func: Callable) -> Callable:
    """Decorator to enforce that the user is authenticated and active."""
    @functools.wraps(view_func)
    def decorated_view(*args: Any, **kwargs: Any) -> Any:
        if not g.get("user"):
            if is_api_request():
                return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
            return redirect(url_for("auth.login_page", next=request.full_path if request.method == "GET" else None))

        if g.user.get("status") == "disabled":
            session.clear()
            if is_api_request():
                return jsonify({"error": "Forbidden", "message": "Your account has been disabled"}), 403
            return render_template("auth/error.html", title="Account Disabled", message="Your account has been deactivated by an administrator."), 403

        return view_func(*args, **kwargs)
    return decorated_view


def require_role(*allowed_roles: str) -> Callable:
    """Decorator to enforce that the user possesses one of the specified roles."""
    def decorator(view_func: Callable) -> Callable:
        @functools.wraps(view_func)
        def decorated_view(*args: Any, **kwargs: Any) -> Any:
            if not g.get("user"):
                if is_api_request():
                    return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
                return redirect(url_for("auth.login_page"))

            # SUPERADMIN always satisfies all role requirements
            if g.get("is_superadmin") or g.get("current_role") in allowed_roles:
                return view_func(*args, **kwargs)

            # Denied
            log_audit_event(
                actor_user_id=g.user.get("user_id"),
                actor_email=g.user.get("email"),
                tenant_id=g.current_tenant.get("tenant_id") if g.current_tenant else None,
                action="role_access_denied",
                resource_type="route",
                resource_id=request.path,
                result="forbidden",
                details=f"Required roles: {allowed_roles}, user role: {g.get('current_role')}",
            )

            if is_api_request():
                return jsonify({"error": "Forbidden", "message": "You do not have permission to access this resource"}), 403
            return render_template("auth/error.html", title="403 Forbidden", message="You do not have permission to perform this action."), 403

        return decorated_view
    return decorator


def require_permission(permission: str) -> Callable:
    """Decorator to enforce a specific granular permission."""
    def decorator(view_func: Callable) -> Callable:
        @functools.wraps(view_func)
        def decorated_view(*args: Any, **kwargs: Any) -> Any:
            if not g.get("user"):
                if is_api_request():
                    return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
                return redirect(url_for("auth.login_page"))

            current_role = g.get("current_role", ROLE_CLIENT)
            if g.get("is_superadmin") or has_permission(current_role, permission):
                return view_func(*args, **kwargs)

            log_audit_event(
                actor_user_id=g.user.get("user_id"),
                actor_email=g.user.get("email"),
                tenant_id=g.current_tenant.get("tenant_id") if g.current_tenant else None,
                action="permission_denied",
                resource_type="permission",
                resource_id=permission,
                result="forbidden",
            )

            if is_api_request():
                return jsonify({"error": "Forbidden", "message": f"Missing required permission: {permission}"}), 403
            return render_template("auth/error.html", title="403 Forbidden", message="Access restricted."), 403

        return decorated_view
    return decorator


def require_tenant_scan_access(view_func: Callable) -> Callable:
    """Decorator to enforce tenant isolation on scan-specific routes."""
    @functools.wraps(view_func)
    def decorated_view(*args: Any, **kwargs: Any) -> Any:
        if not g.get("user"):
            if is_api_request():
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("auth.login_page"))

        scan_id = kwargs.get("scan_id") or request.args.get("scan_id") or (request.get_json(silent=True) or {}).get("scan_id")
        if not scan_id:
            # If no scan_id present in route, proceed to standard handler
            return view_func(*args, **kwargs)

        # Platform SUPERADMIN can access any scan
        if g.get("is_superadmin"):
            return view_func(*args, **kwargs)

        ownership = get_scan_ownership(scan_id)
        if not ownership:
            # If not yet registered in ownership table, bind to current tenant if caller is creator/admin
            if g.current_tenant:
                return view_func(*args, **kwargs)
            if is_api_request():
                return jsonify({"error": "Forbidden", "message": "Access denied"}), 403
            return render_template("auth/error.html", title="403 Forbidden", message="Scan not found or access denied."), 403

        target_tenant_id = ownership.get("tenant_id")
        current_tenant_id = g.current_tenant.get("tenant_id") if g.current_tenant else None

        if target_tenant_id != current_tenant_id:
            log_audit_event(
                actor_user_id=g.user.get("user_id"),
                actor_email=g.user.get("email"),
                tenant_id=current_tenant_id,
                action="cross_tenant_scan_access_blocked",
                resource_type="scan",
                resource_id=scan_id,
                result="forbidden",
                details=f"Attempted to access scan belonging to {target_tenant_id}",
            )
            if is_api_request():
                return jsonify({"error": "Forbidden", "message": "Access denied to cross-tenant resource"}), 403
            return render_template("auth/error.html", title="403 Forbidden", message="You do not have permission to access this organization's scan."), 403

        return view_func(*args, **kwargs)
    return decorated_view
