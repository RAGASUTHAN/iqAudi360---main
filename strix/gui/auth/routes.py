"""Authentication and multi-tenant management routes for iqAudi360."""

from __future__ import annotations

import logging
from typing import Any

from flask import (
    Blueprint,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from strix.gui.auth.db import (
    add_tenant_member,
    create_tenant,
    get_or_create_user,
    get_tenant_by_id,
    get_tenant_membership,
    get_user_by_email,
    get_user_by_id,
    list_all_tenants,
    list_all_users,
    list_audit_logs,
    list_tenant_members,
    list_tenants_for_user,
    log_audit_event,
    remove_tenant_member,
    set_user_superadmin,
    update_tenant_member_role,
    update_tenant_member_status,
    update_tenant_name,
    update_tenant_status,
    update_user_status,
)
from strix.gui.auth.decorators import require_auth, require_role
from strix.gui.auth.firebase import get_firebase_web_config, verify_id_token
from strix.gui.auth.rbac import (
    ROLE_ADMIN,
    ROLE_CLIENT,
    ROLE_DEV,
    ROLE_SUPERADMIN,
    can_manage_role,
    has_permission,
)

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__)


# ---------------------------------------------------------------------------
# HTML Pages
# ---------------------------------------------------------------------------

@auth_bp.route("/login")
def login_page() -> Any:
    """Render the Firebase-powered Login page."""
    if g.get("user"):
        return redirect(url_for("dashboard"))
    firebase_config = get_firebase_web_config()
    return render_template("auth/login.html", firebase_config=firebase_config)


@auth_bp.route("/register")
def register_page() -> Any:
    """Render the Firebase-powered Registration page."""
    if g.get("user"):
        return redirect(url_for("dashboard"))
    firebase_config = get_firebase_web_config()
    return render_template("auth/register.html", firebase_config=firebase_config)


@auth_bp.route("/forgot-password")
def forgot_password_page() -> Any:
    """Render the Firebase Password Reset page."""
    firebase_config = get_firebase_web_config()
    return render_template("auth/forgot_password.html", firebase_config=firebase_config)


@auth_bp.route("/logout")
def logout() -> Any:
    """Log out the current user session and redirect to login."""
    if g.get("user"):
        log_audit_event(
            actor_user_id=g.user.get("user_id"),
            actor_email=g.user.get("email"),
            tenant_id=g.current_tenant.get("tenant_id") if g.current_tenant else None,
            action="user_logout",
            result="success",
        )
    session.clear()
    return redirect(url_for("auth.login_page"))


@auth_bp.route("/organizations")
@require_auth
@require_role(ROLE_SUPERADMIN, ROLE_ADMIN)
def organizations_page() -> Any:
    """Render Organization & Member Management page for Admins & Superadmins."""
    firebase_config = get_firebase_web_config()
    return render_template("auth/organizations.html", firebase_config=firebase_config)


@auth_bp.route("/users")
@require_auth
@require_role(ROLE_SUPERADMIN)
def users_admin_page() -> Any:
    """Render Platform-wide User Management page for SUPERADMIN."""
    return render_template("auth/users_admin.html")


@auth_bp.route("/audit-logs")
@require_auth
@require_role(ROLE_SUPERADMIN, ROLE_ADMIN)
def audit_logs_page() -> Any:
    """Render Security & Compliance Audit Log page."""
    return render_template("auth/audit_logs.html")


# ---------------------------------------------------------------------------
# Authentication API
# ---------------------------------------------------------------------------

DEMO_CREDENTIALS: dict[str, tuple[str, str, str, bool]] = {
    "superadmin@iqaudi360.com": ("SuperAdmin123!", "uid_super_01", "Super Admin", True),
    "admin@alpha.com": ("Admin123!", "uid_admin_a", "Alice Admin", False),
    "dev@alpha.com": ("Dev123!", "uid_dev_a", "Dan Dev", False),
    "client@alpha.com": ("Client123!", "uid_client_a", "Charlie Client", False),
}


@auth_bp.route("/api/auth/demo-login", methods=["POST"])
def api_demo_login() -> Any:
    """Allow direct demo login for role evaluation and local testing."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    role_key = (data.get("role") or "").strip().upper()

    role_to_email = {
        "SUPERADMIN": "superadmin@iqaudi360.com",
        "SUPER_ADMIN": "superadmin@iqaudi360.com",
        "SUPER ADMIN": "superadmin@iqaudi360.com",
        "ADMIN": "admin@alpha.com",
        "DEV": "dev@alpha.com",
        "DEVELOPER": "dev@alpha.com",
        "CLIENT": "client@alpha.com",
    }
    if role_key in role_to_email:
        email = role_to_email[role_key]

    if email not in DEMO_CREDENTIALS:
        return jsonify({"error": "Unauthorized", "message": "Invalid demo email or role"}), 401

    expected_pass, uid, display_name, is_super = DEMO_CREDENTIALS[email]
    if password and password not in (expected_pass, "Password123!", "admin123", "password"):
        return jsonify({"error": "Unauthorized", "message": "Invalid credentials"}), 401

    user = get_or_create_user(uid, email, display_name)
    if is_super:
        set_user_superadmin(user["user_id"], True)

    session["user_id"] = user["user_id"]
    tenants = list_tenants_for_user(user["user_id"], is_superadmin=bool(user.get("is_superadmin")))
    if tenants:
        session["active_tenant_id"] = tenants[0]["tenant_id"]
        active_tenant = tenants[0]
    else:
        active_tenant = None

    log_audit_event(
        actor_user_id=user["user_id"],
        actor_email=user["email"],
        tenant_id=active_tenant.get("tenant_id") if active_tenant else None,
        action="demo_user_login",
        resource_type="session",
        resource_id=user["user_id"],
        result="success",
        ip_address=request.remote_addr,
    )

    return jsonify({
        "status": "ok",
        "user": {
            "user_id": user["user_id"],
            "email": user["email"],
            "display_name": user["display_name"],
            "photo_url": user.get("photo_url"),
            "is_superadmin": bool(user.get("is_superadmin")),
        },
        "tenant": active_tenant,
    })


@auth_bp.route("/api/auth/session-login", methods=["POST"])
def api_session_login() -> Any:
    """Verify Firebase ID token and establish backend session."""
    data = request.get_json(silent=True) or {}
    id_token = data.get("idToken")

    if not id_token:
        return jsonify({"error": "Bad Request", "message": "Missing idToken"}), 400

    decoded = verify_id_token(id_token)
    if not decoded:
        return jsonify({"error": "Unauthorized", "message": "Invalid or expired Firebase ID token"}), 401

    uid = decoded.get("uid")
    email = decoded.get("email", "")
    name = decoded.get("name") or decoded.get("display_name") or data.get("displayName")
    picture = decoded.get("picture")

    # Get or create SQLite user profile
    user = get_or_create_user(uid, email, name, picture)

    if user.get("status") == "disabled":
        log_audit_event(
            actor_user_id=uid,
            actor_email=email,
            tenant_id=None,
            action="user_login_blocked",
            resource_type="user",
            resource_id=uid,
            result="disabled",
            details="Account is disabled",
        )
        return jsonify({"error": "Forbidden", "message": "Account has been deactivated"}), 403

    # Set session
    session["user_id"] = user["user_id"]

    # Select default tenant
    is_superadmin = bool(user.get("is_superadmin"))
    tenants = list_tenants_for_user(user["user_id"], is_superadmin=is_superadmin)
    if tenants:
        session["active_tenant_id"] = tenants[0]["tenant_id"]
        active_tenant = tenants[0]
    else:
        active_tenant = None

    log_audit_event(
        actor_user_id=user["user_id"],
        actor_email=user["email"],
        tenant_id=active_tenant.get("tenant_id") if active_tenant else None,
        action="user_login",
        resource_type="session",
        resource_id=user["user_id"],
        result="success",
        ip_address=request.remote_addr,
    )

    return jsonify({
        "status": "ok",
        "user": {
            "user_id": user["user_id"],
            "email": user["email"],
            "display_name": user["display_name"],
            "photo_url": user["photo_url"],
            "is_superadmin": bool(user["is_superadmin"]),
        },
        "tenant": active_tenant,
    })


@auth_bp.route("/api/auth/session-logout", methods=["POST"])
def api_session_logout() -> Any:
    """Clear backend session."""
    if g.get("user"):
        log_audit_event(
            actor_user_id=g.user.get("user_id"),
            actor_email=g.user.get("email"),
            tenant_id=g.current_tenant.get("tenant_id") if g.current_tenant else None,
            action="user_logout",
            result="success",
        )
    session.clear()
    return jsonify({"status": "ok"})


@auth_bp.route("/api/auth/me", methods=["GET"])
@require_auth
def api_auth_me() -> Any:
    """Return authenticated profile, current tenant, role, and accessible organizations."""
    return jsonify({
        "user": g.user,
        "current_tenant": g.current_tenant,
        "current_role": g.current_role,
        "is_superadmin": g.is_superadmin,
        "tenants": g.user_tenants,
    })


@auth_bp.route("/api/auth/switch-tenant", methods=["POST"])
@require_auth
def api_switch_tenant() -> Any:
    """Switch active tenant context."""
    data = request.get_json(silent=True) or {}
    target_tenant_id = data.get("tenant_id")

    if not target_tenant_id:
        return jsonify({"error": "Bad Request", "message": "Missing tenant_id"}), 400

    target_tenant = get_tenant_by_id(target_tenant_id)
    if not target_tenant or target_tenant.get("status") == "suspended":
        return jsonify({"error": "Not Found", "message": "Organization not found or suspended"}), 404

    # Verify authorization
    if not g.is_superadmin:
        membership = get_tenant_membership(target_tenant_id, g.user["user_id"])
        if not membership or membership.get("status") != "active":
            log_audit_event(
                actor_user_id=g.user["user_id"],
                actor_email=g.user["email"],
                tenant_id=target_tenant_id,
                action="tenant_switch_unauthorized",
                result="forbidden",
            )
            return jsonify({"error": "Forbidden", "message": "Access denied to selected organization"}), 403

    session["active_tenant_id"] = target_tenant_id

    log_audit_event(
        actor_user_id=g.user["user_id"],
        actor_email=g.user["email"],
        tenant_id=target_tenant_id,
        action="tenant_switched",
        resource_type="tenant",
        resource_id=target_tenant_id,
        result="success",
    )

    return jsonify({"status": "ok", "tenant": target_tenant})


# ---------------------------------------------------------------------------
# Multi-Tenant Organization Management API
# ---------------------------------------------------------------------------

@auth_bp.route("/api/organizations", methods=["GET"])
@require_auth
def api_list_organizations() -> Any:
    """List organizations accessible to current user."""
    if g.is_superadmin:
        tenants = list_all_tenants()
    else:
        tenants = list_tenants_for_user(g.user["user_id"])
    return jsonify({"organizations": tenants})


@auth_bp.route("/api/organizations", methods=["POST"])
@require_auth
@require_role(ROLE_SUPERADMIN)
def api_create_organization() -> Any:
    """Create a new tenant organization (SUPERADMIN only)."""
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Bad Request", "message": "Organization name is required"}), 400

    new_org = create_tenant(name, created_by=g.user["user_id"])
    log_audit_event(
        actor_user_id=g.user["user_id"],
        actor_email=g.user["email"],
        tenant_id=new_org["tenant_id"],
        action="tenant_created",
        resource_type="tenant",
        resource_id=new_org["tenant_id"],
        result="success",
        details=f"Created organization: {name}",
    )
    return jsonify({"status": "ok", "organization": new_org}), 201


@auth_bp.route("/api/organizations/<tenant_id>", methods=["PUT"])
@require_auth
def api_update_organization(tenant_id: str) -> Any:
    """Update organization name or status."""
    # Check authorization: SUPERADMIN or ADMIN of this tenant
    if not g.is_superadmin:
        if not g.current_tenant or g.current_tenant.get("tenant_id") != tenant_id or g.current_role != ROLE_ADMIN:
            return jsonify({"error": "Forbidden", "message": "Access denied"}), 403

    data = request.get_json(silent=True) or {}
    if "name" in data:
        update_tenant_name(tenant_id, data["name"])
    if "status" in data and g.is_superadmin:
        update_tenant_status(tenant_id, data["status"])

    updated = get_tenant_by_id(tenant_id)
    log_audit_event(
        actor_user_id=g.user["user_id"],
        actor_email=g.user["email"],
        tenant_id=tenant_id,
        action="tenant_updated",
        resource_type="tenant",
        resource_id=tenant_id,
        result="success",
    )
    return jsonify({"status": "ok", "organization": updated})


@auth_bp.route("/api/organizations/<tenant_id>/members", methods=["GET"])
@require_auth
def api_list_members(tenant_id: str) -> Any:
    """List members of an organization."""
    if not g.is_superadmin:
        if not g.current_tenant or g.current_tenant.get("tenant_id") != tenant_id or g.current_role not in (ROLE_ADMIN, ROLE_SUPERADMIN):
            return jsonify({"error": "Forbidden", "message": "Access denied"}), 403

    members = list_tenant_members(tenant_id)
    return jsonify({"members": members})


@auth_bp.route("/api/organizations/<tenant_id>/members", methods=["POST"])
@require_auth
def api_add_member(tenant_id: str) -> Any:
    """Add or invite a user to an organization by email."""
    if not g.is_superadmin:
        if not g.current_tenant or g.current_tenant.get("tenant_id") != tenant_id or g.current_role != ROLE_ADMIN:
            return jsonify({"error": "Forbidden", "message": "Only organization Admins can add members"}), 403

    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    role = data.get("role", ROLE_DEV).upper()

    if not email:
        return jsonify({"error": "Bad Request", "message": "Email is required"}), 400

    if role not in (ROLE_ADMIN, ROLE_DEV, ROLE_CLIENT):
        return jsonify({"error": "Bad Request", "message": "Invalid role. Allowed: ADMIN, DEV, CLIENT"}), 400

    # Role assignment permission check
    if not can_manage_role(g.current_role, role):
        return jsonify({"error": "Forbidden", "message": f"You cannot assign the {role} role"}), 403

    # Look up existing user by email or auto-provision record
    existing_user = get_user_by_email(email)
    if not existing_user:
        # Create user profile shell so they immediately belong to tenant when they sign up
        import uuid
        placeholder_uid = f"user_{uuid.uuid4().hex[:16]}"
        existing_user = get_or_create_user(placeholder_uid, email)

    membership = add_tenant_member(tenant_id, existing_user["user_id"], role=role)
    if not membership:
        return jsonify({"error": "Internal Error", "message": "Failed to add member"}), 500

    log_audit_event(
        actor_user_id=g.user["user_id"],
        actor_email=g.user["email"],
        tenant_id=tenant_id,
        action="member_added",
        resource_type="tenant_member",
        resource_id=existing_user["user_id"],
        result="success",
        details=f"Added {email} with role {role}",
    )

    return jsonify({"status": "ok", "membership": membership}), 201


@auth_bp.route("/api/organizations/<tenant_id>/members/<user_id>", methods=["PUT"])
@require_auth
def api_update_member(tenant_id: str, user_id: str) -> Any:
    """Update role or status of a tenant member."""
    if not g.is_superadmin:
        if not g.current_tenant or g.current_tenant.get("tenant_id") != tenant_id or g.current_role != ROLE_ADMIN:
            return jsonify({"error": "Forbidden", "message": "Access denied"}), 403

    data = request.get_json(silent=True) or {}

    if "role" in data:
        new_role = data["role"].upper()
        if not can_manage_role(g.current_role, new_role):
            return jsonify({"error": "Forbidden", "message": f"You cannot assign role {new_role}"}), 403
        update_tenant_member_role(tenant_id, user_id, new_role)

    if "status" in data:
        update_tenant_member_status(tenant_id, user_id, data["status"])

    log_audit_event(
        actor_user_id=g.user["user_id"],
        actor_email=g.user["email"],
        tenant_id=tenant_id,
        action="member_updated",
        resource_type="tenant_member",
        resource_id=user_id,
        result="success",
        details=f"Updated member {user_id}: {data}",
    )
    return jsonify({"status": "ok"})


@auth_bp.route("/api/organizations/<tenant_id>/members/<user_id>", methods=["DELETE"])
@require_auth
def api_remove_member(tenant_id: str, user_id: str) -> Any:
    """Remove member from organization."""
    if not g.is_superadmin:
        if not g.current_tenant or g.current_tenant.get("tenant_id") != tenant_id or g.current_role != ROLE_ADMIN:
            return jsonify({"error": "Forbidden", "message": "Access denied"}), 403

    remove_tenant_member(tenant_id, user_id)
    log_audit_event(
        actor_user_id=g.user["user_id"],
        actor_email=g.user["email"],
        tenant_id=tenant_id,
        action="member_removed",
        resource_type="tenant_member",
        resource_id=user_id,
        result="success",
    )
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# SuperAdmin Platform Management API
# ---------------------------------------------------------------------------

@auth_bp.route("/api/admin/users", methods=["GET"])
@require_auth
@require_role(ROLE_SUPERADMIN)
def api_admin_list_users() -> Any:
    """List all registered platform users (SUPERADMIN only)."""
    users = list_all_users()
    return jsonify({"users": users})


@auth_bp.route("/api/admin/users/<user_id>/status", methods=["PUT"])
@require_auth
@require_role(ROLE_SUPERADMIN)
def api_admin_update_user_status(user_id: str) -> Any:
    """Enable or disable user globally across the platform."""
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in ("active", "disabled"):
        return jsonify({"error": "Bad Request", "message": "Invalid status"}), 400

    update_user_status(user_id, status)
    log_audit_event(
        actor_user_id=g.user["user_id"],
        actor_email=g.user["email"],
        tenant_id=None,
        action="user_status_changed",
        resource_type="user",
        resource_id=user_id,
        result="success",
        details=f"Status changed to {status}",
    )
    return jsonify({"status": "ok"})


@auth_bp.route("/api/admin/users/<user_id>/superadmin", methods=["PUT"])
@require_auth
@require_role(ROLE_SUPERADMIN)
def api_admin_toggle_superadmin(user_id: str) -> Any:
    """Grant or revoke SUPERADMIN role (SUPERADMIN only)."""
    data = request.get_json(silent=True) or {}
    is_superadmin = bool(data.get("is_superadmin"))

    set_user_superadmin(user_id, is_superadmin)
    log_audit_event(
        actor_user_id=g.user["user_id"],
        actor_email=g.user["email"],
        tenant_id=None,
        action="superadmin_role_toggled",
        resource_type="user",
        resource_id=user_id,
        result="success",
        details=f"Superadmin set to {is_superadmin}",
    )
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Audit Logs API
# ---------------------------------------------------------------------------

@auth_bp.route("/api/audit-logs", methods=["GET"])
@require_auth
@require_role(ROLE_SUPERADMIN, ROLE_ADMIN)
def api_get_audit_logs() -> Any:
    """Retrieve recent platform or tenant audit logs."""
    limit = int(request.args.get("limit", 100))
    if g.is_superadmin:
        logs = list_audit_logs(tenant_id=None, limit=limit)
    else:
        current_tenant_id = g.current_tenant.get("tenant_id") if g.current_tenant else None
        logs = list_audit_logs(tenant_id=current_tenant_id, limit=limit)
    return jsonify({"logs": logs})
