"""Role-Based Access Control (RBAC) definitions and permission matrix for iqAudi360."""

from __future__ import annotations

from typing import Final

# Exact 4 user-facing platform roles
ROLE_SUPERADMIN: Final[str] = "SUPERADMIN"
ROLE_ADMIN: Final[str] = "ADMIN"
ROLE_DEV: Final[str] = "DEV"
ROLE_CLIENT: Final[str] = "CLIENT"

ALL_ROLES: Final[tuple[str, ...]] = (
    ROLE_SUPERADMIN,
    ROLE_ADMIN,
    ROLE_DEV,
    ROLE_CLIENT,
)

# Permissions
PERM_PLATFORM_MANAGE: Final[str] = "platform:manage"        # View/manage all tenants, system diagnostics, global settings
PERM_ORG_MANAGE: Final[str] = "org:manage"                  # Edit own organization settings, view members
PERM_USER_MANAGE: Final[str] = "user:manage"                # Invite, remove, change roles of DEV/CLIENT
PERM_SCAN_CREATE: Final[str] = "scan:create"                # Configure new scans
PERM_SCAN_START: Final[str] = "scan:start"                  # Launch scan execution
PERM_SCAN_STOP: Final[str] = "scan:stop"                    # Abort active scan
PERM_LOGS_VIEW: Final[str] = "logs:view"                    # View raw execution logs, terminal stream, agent activity
PERM_FINDINGS_VIEW: Final[str] = "findings:view"            # View vulnerability cards & details
PERM_REPORTS_VIEW: Final[str] = "reports:view"              # View scan executive & technical reports
PERM_REPORTS_DOWNLOAD: Final[str] = "reports:download"      # Download HTML, PDF, DOCX, SARIF reports
PERM_AUDIT_VIEW: Final[str] = "audit:view"                  # View audit event logs

# Permission mapping per role
ROLE_PERMISSIONS: dict[str, set[str]] = {
    ROLE_SUPERADMIN: {
        PERM_PLATFORM_MANAGE,
        PERM_ORG_MANAGE,
        PERM_USER_MANAGE,
        PERM_SCAN_CREATE,
        PERM_SCAN_START,
        PERM_SCAN_STOP,
        PERM_LOGS_VIEW,
        PERM_FINDINGS_VIEW,
        PERM_REPORTS_VIEW,
        PERM_REPORTS_DOWNLOAD,
        PERM_AUDIT_VIEW,
    },
    ROLE_ADMIN: {
        PERM_ORG_MANAGE,
        PERM_USER_MANAGE,
        PERM_SCAN_CREATE,
        PERM_SCAN_START,
        PERM_SCAN_STOP,
        PERM_LOGS_VIEW,
        PERM_FINDINGS_VIEW,
        PERM_REPORTS_VIEW,
        PERM_REPORTS_DOWNLOAD,
        PERM_AUDIT_VIEW,
    },
    ROLE_DEV: {
        PERM_SCAN_CREATE,
        PERM_SCAN_START,
        PERM_SCAN_STOP,
        PERM_LOGS_VIEW,
        PERM_FINDINGS_VIEW,
        PERM_REPORTS_VIEW,
        PERM_REPORTS_DOWNLOAD,
    },
    ROLE_CLIENT: {
        PERM_FINDINGS_VIEW,
        PERM_REPORTS_VIEW,
        PERM_REPORTS_DOWNLOAD,
    },
}


def has_permission(role: str, permission: str) -> bool:
    """Check if a given role has the requested permission."""
    permissions = ROLE_PERMISSIONS.get(role, set())
    return permission in permissions


def can_manage_role(actor_role: str, target_role: str) -> bool:
    """Check if the actor role is authorized to assign or modify the target role."""
    if actor_role == ROLE_SUPERADMIN:
        return True
    if actor_role == ROLE_ADMIN:
        # ADMIN can only manage DEV and CLIENT
        return target_role in (ROLE_DEV, ROLE_CLIENT)
    return False
