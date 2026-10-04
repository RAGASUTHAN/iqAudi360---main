"""SQLite persistent database layer for multi-tenant organizations, users, RBAC & audit logging."""

from __future__ import annotations

import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from strix.core.paths import runs_base_dir

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).resolve().parent.parent.parent.parent / "iqaudi360_auth.db"


def get_db_connection() -> sqlite3.Connection:
    """Create a thread-safe connection to the SQLite auth database."""
    conn = sqlite3.connect(str(DB_PATH), timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    """Initialize database schema and tables."""
    conn = get_db_connection()
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            display_name TEXT,
            photo_url TEXT,
            is_superadmin INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            last_login_at TEXT
        );

        CREATE TABLE IF NOT EXISTS tenants (
            tenant_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_by TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            FOREIGN KEY (created_by) REFERENCES users(user_id)
        );

        CREATE TABLE IF NOT EXISTS tenant_members (
            membership_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            UNIQUE(tenant_id, user_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS scan_ownership (
            scan_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            actor_user_id TEXT,
            actor_email TEXT,
            tenant_id TEXT,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            result TEXT NOT NULL,
            ip_address TEXT,
            details TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_tenant_members_user ON tenant_members(user_id);
        CREATE INDEX IF NOT EXISTS idx_tenant_members_tenant ON tenant_members(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_scan_ownership_tenant ON scan_ownership(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant ON audit_logs(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
        """)
    conn.close()
    logger.info("iqAudi360 multi-tenant database initialized at: %s", DB_PATH)
    seed_demo_accounts()
    _migrate_existing_scans()


def seed_demo_accounts() -> None:
    """Ensure standard platform demo accounts exist for SUPERADMIN, ADMIN, DEV, and CLIENT."""
    conn = get_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            # 1. Superadmin user
            conn.execute("""
            INSERT OR IGNORE INTO users (user_id, email, display_name, photo_url, is_superadmin, status, created_at, last_login_at)
            VALUES ('uid_super_01', 'superadmin@iqaudi360.com', 'Super Admin', NULL, 1, 'active', ?, ?)
            """, (now_iso, now_iso))
            conn.execute("UPDATE users SET is_superadmin = 1, status = 'active' WHERE user_id = 'uid_super_01'")

            # 2. Org Alpha
            conn.execute("""
            INSERT OR IGNORE INTO tenants (tenant_id, name, created_by, status, created_at)
            VALUES ('org_alpha_workspace', 'Enterprise Org Alpha', 'uid_super_01', 'active', ?)
            """, (now_iso,))

            # Superadmin membership in Org Alpha
            conn.execute("""
            INSERT OR IGNORE INTO tenant_members (membership_id, tenant_id, user_id, role, status, created_at)
            VALUES ('mem_super_alpha', 'org_alpha_workspace', 'uid_super_01', 'ADMIN', 'active', ?)
            """, (now_iso,))

            # 3. Admin user
            conn.execute("""
            INSERT OR IGNORE INTO users (user_id, email, display_name, photo_url, is_superadmin, status, created_at, last_login_at)
            VALUES ('uid_admin_a', 'admin@alpha.com', 'Alice Admin', NULL, 0, 'active', ?, ?)
            """, (now_iso, now_iso))
            conn.execute("""
            INSERT OR IGNORE INTO tenant_members (membership_id, tenant_id, user_id, role, status, created_at)
            VALUES ('mem_admin_alpha', 'org_alpha_workspace', 'uid_admin_a', 'ADMIN', 'active', ?)
            """, (now_iso,))

            # 4. Dev user
            conn.execute("""
            INSERT OR IGNORE INTO users (user_id, email, display_name, photo_url, is_superadmin, status, created_at, last_login_at)
            VALUES ('uid_dev_a', 'dev@alpha.com', 'Dan Dev', NULL, 0, 'active', ?, ?)
            """, (now_iso, now_iso))
            conn.execute("""
            INSERT OR IGNORE INTO tenant_members (membership_id, tenant_id, user_id, role, status, created_at)
            VALUES ('mem_dev_alpha', 'org_alpha_workspace', 'uid_dev_a', 'DEV', 'active', ?)
            """, (now_iso,))

            # 5. Client user
            conn.execute("""
            INSERT OR IGNORE INTO users (user_id, email, display_name, photo_url, is_superadmin, status, created_at, last_login_at)
            VALUES ('uid_client_a', 'client@alpha.com', 'Charlie Client', NULL, 0, 'active', ?, ?)
            """, (now_iso, now_iso))
            conn.execute("""
            INSERT OR IGNORE INTO tenant_members (membership_id, tenant_id, user_id, role, status, created_at)
            VALUES ('mem_client_alpha', 'org_alpha_workspace', 'uid_client_a', 'CLIENT', 'active', ?)
            """, (now_iso,))
    except Exception as exc:
        logger.debug("seed_demo_accounts info: %s", exc)
    finally:
        conn.close()


def _migrate_existing_scans() -> None:
    """Ensure any existing pre-auth scans are mapped to the default organization."""
    try:
        base_dir = runs_base_dir()
        if not base_dir.is_dir():
            return

        conn = get_db_connection()
        default_tenant = None

        with conn:
            # Check if default organization exists
            cur = conn.execute("SELECT tenant_id FROM tenants ORDER BY created_at ASC LIMIT 1")
            row = cur.fetchone()
            if row:
                default_tenant = row["tenant_id"]

            if default_tenant:
                for child in base_dir.iterdir():
                    if child.is_dir():
                        scan_id = child.name
                        conn.execute("""
                        INSERT OR IGNORE INTO scan_ownership (scan_id, tenant_id, created_by, created_at)
                        VALUES (?, ?, ?, ?)
                        """, (scan_id, default_tenant, "system_bootstrap", datetime.now(timezone.utc).isoformat()))
        conn.close()
    except Exception as exc:
        logger.debug("Existing scans migration check: %s", exc)


def get_or_create_user(
    uid: str,
    email: str,
    display_name: str | None = None,
    photo_url: str | None = None,
) -> dict[str, Any]:
    """Retrieve existing user or create a new user profile upon Firebase login."""
    conn = get_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()

    with conn:
        cur = conn.execute("SELECT * FROM users WHERE user_id = ?", (uid,))
        user_row = cur.fetchone()

        if user_row:
            # Update last login
            conn.execute(
                "UPDATE users SET last_login_at = ?, display_name = COALESCE(?, display_name) WHERE user_id = ?",
                (now_iso, display_name, uid),
            )
            cur = conn.execute("SELECT * FROM users WHERE user_id = ?", (uid,))
            return dict(cur.fetchone())

        # Check total user count to determine initial SUPERADMIN bootstrap
        cur = conn.execute("SELECT COUNT(*) as total FROM users")
        total_users = cur.fetchone()["total"]
        is_first_user = (total_users == 0)

        is_superadmin = 1 if is_first_user else 0
        name = display_name or email.split("@")[0].capitalize()

        conn.execute("""
        INSERT INTO users (user_id, email, display_name, photo_url, is_superadmin, status, created_at, last_login_at)
        VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
        """, (uid, email.lower(), name, photo_url, is_superadmin, now_iso, now_iso))

        # Create organization for the user
        tenant_id = f"org_{uuid.uuid4().hex[:12]}"
        org_name = "Primary Security Workspace" if is_first_user else f"{name}'s Organization"

        conn.execute("""
        INSERT INTO tenants (tenant_id, name, created_by, status, created_at)
        VALUES (?, ?, ?, 'active', ?)
        """, (tenant_id, org_name, uid, now_iso))

        # Assign creator as ADMIN
        membership_id = f"mem_{uuid.uuid4().hex[:12]}"
        conn.execute("""
        INSERT INTO tenant_members (membership_id, tenant_id, user_id, role, status, created_at)
        VALUES (?, ?, ?, 'ADMIN', 'active', ?)
        """, (membership_id, tenant_id, uid, now_iso))

        # Also migrate any loose scan records to this primary organization
        if is_first_user:
            _migrate_existing_scans()

        cur = conn.execute("SELECT * FROM users WHERE user_id = ?", (uid,))
        created_user = dict(cur.fetchone())

    conn.close()
    return created_user


def get_user_by_id(uid: str) -> dict[str, Any] | None:
    """Fetch user record by Firebase UID."""
    conn = get_db_connection()
    cur = conn.execute("SELECT * FROM users WHERE user_id = ?", (uid,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_email(email: str) -> dict[str, Any] | None:
    """Fetch user record by email address."""
    conn = get_db_connection()
    cur = conn.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def list_all_users() -> list[dict[str, Any]]:
    """List all platform users (for SUPERADMIN)."""
    conn = get_db_connection()
    cur = conn.execute("SELECT * FROM users ORDER BY created_at DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def update_user_status(uid: str, status: str) -> bool:
    """Update user account status ('active' or 'disabled')."""
    if status not in ("active", "disabled"):
        return False
    conn = get_db_connection()
    with conn:
        conn.execute("UPDATE users SET status = ? WHERE user_id = ?", (status, uid))
    conn.close()
    return True


def set_user_superadmin(uid: str, is_superadmin: bool) -> bool:
    """Set or revoke platform SUPERADMIN status."""
    conn = get_db_connection()
    with conn:
        conn.execute("UPDATE users SET is_superadmin = ? WHERE user_id = ?", (1 if is_superadmin else 0, uid))
    conn.close()
    return True


def create_tenant(name: str, created_by: str) -> dict[str, Any]:
    """Create a new multi-tenant organization."""
    conn = get_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    tenant_id = f"org_{uuid.uuid4().hex[:12]}"
    membership_id = f"mem_{uuid.uuid4().hex[:12]}"

    with conn:
        conn.execute("""
        INSERT INTO tenants (tenant_id, name, created_by, status, created_at)
        VALUES (?, ?, ?, 'active', ?)
        """, (tenant_id, name.strip(), created_by, now_iso))

        conn.execute("""
        INSERT INTO tenant_members (membership_id, tenant_id, user_id, role, status, created_at)
        VALUES (?, ?, ?, 'ADMIN', 'active', ?)
        """, (membership_id, tenant_id, created_by, now_iso))

        cur = conn.execute("SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,))
        tenant = dict(cur.fetchone())

    conn.close()
    return tenant


def get_tenant_by_id(tenant_id: str) -> dict[str, Any] | None:
    """Fetch organization by tenant_id."""
    conn = get_db_connection()
    cur = conn.execute("SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def list_tenants_for_user(user_id: str, is_superadmin: bool = False) -> list[dict[str, Any]]:
    """List all organizations accessible to a user."""
    conn = get_db_connection()
    if is_superadmin:
        cur = conn.execute("SELECT * FROM tenants ORDER BY created_at DESC")
    else:
        cur = conn.execute("""
        SELECT t.*, tm.role, tm.status as member_status 
        FROM tenants t
        JOIN tenant_members tm ON t.tenant_id = tm.tenant_id
        WHERE tm.user_id = ? AND tm.status = 'active' AND t.status = 'active'
        ORDER BY t.created_at DESC
        """, (user_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def list_all_tenants() -> list[dict[str, Any]]:
    """List all organizations across the platform (for SUPERADMIN)."""
    conn = get_db_connection()
    cur = conn.execute("""
    SELECT t.*, 
           (SELECT COUNT(*) FROM tenant_members WHERE tenant_id = t.tenant_id) as member_count,
           (SELECT COUNT(*) FROM scan_ownership WHERE tenant_id = t.tenant_id) as scan_count
    FROM tenants t 
    ORDER BY t.created_at DESC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def update_tenant_status(tenant_id: str, status: str) -> bool:
    """Update organization status ('active' or 'suspended')."""
    if status not in ("active", "suspended"):
        return False
    conn = get_db_connection()
    with conn:
        conn.execute("UPDATE tenants SET status = ? WHERE tenant_id = ?", (status, tenant_id))
    conn.close()
    return True


def update_tenant_name(tenant_id: str, name: str) -> bool:
    """Update organization display name."""
    conn = get_db_connection()
    with conn:
        conn.execute("UPDATE tenants SET name = ? WHERE tenant_id = ?", (name.strip(), tenant_id))
    conn.close()
    return True


def get_tenant_membership(tenant_id: str, user_id: str) -> dict[str, Any] | None:
    """Check membership and role for user in tenant."""
    conn = get_db_connection()
    cur = conn.execute("""
    SELECT tm.*, t.name as tenant_name, t.status as tenant_status
    FROM tenant_members tm
    JOIN tenants t ON tm.tenant_id = t.tenant_id
    WHERE tm.tenant_id = ? AND tm.user_id = ?
    """, (tenant_id, user_id))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def list_tenant_members(tenant_id: str) -> list[dict[str, Any]]:
    """List all members of an organization with user details."""
    conn = get_db_connection()
    cur = conn.execute("""
    SELECT tm.membership_id, tm.tenant_id, tm.user_id, tm.role, tm.status, tm.created_at as joined_at,
           u.email, u.display_name, u.photo_url, u.last_login_at
    FROM tenant_members tm
    JOIN users u ON tm.user_id = u.user_id
    WHERE tm.tenant_id = ?
    ORDER BY tm.created_at ASC
    """, (tenant_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def add_tenant_member(tenant_id: str, user_id: str, role: str = "DEV") -> dict[str, Any] | None:
    """Add user to organization with specified role (ADMIN, DEV, CLIENT)."""
    if role not in ("ADMIN", "DEV", "CLIENT"):
        return None
    conn = get_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    membership_id = f"mem_{uuid.uuid4().hex[:12]}"

    try:
        with conn:
            conn.execute("""
            INSERT INTO tenant_members (membership_id, tenant_id, user_id, role, status, created_at)
            VALUES (?, ?, ?, ?, 'active', ?)
            ON CONFLICT(tenant_id, user_id) DO UPDATE SET role = ?, status = 'active'
            """, (membership_id, tenant_id, user_id, role, now_iso, role))
            cur = conn.execute("SELECT * FROM tenant_members WHERE membership_id = ?", (membership_id,))
            row = cur.fetchone()
            return dict(row) if row else {"membership_id": membership_id, "tenant_id": tenant_id, "user_id": user_id, "role": role}
    except Exception as exc:
        logger.error("Failed to add member to tenant: %s", exc)
        return None
    finally:
        conn.close()


def update_tenant_member_role(tenant_id: str, user_id: str, new_role: str) -> bool:
    """Update role of a member within an organization."""
    if new_role not in ("ADMIN", "DEV", "CLIENT"):
        return False
    conn = get_db_connection()
    with conn:
        conn.execute("""
        UPDATE tenant_members SET role = ? WHERE tenant_id = ? AND user_id = ?
        """, (new_role, tenant_id, user_id))
    conn.close()
    return True


def update_tenant_member_status(tenant_id: str, user_id: str, status: str) -> bool:
    """Disable or enable member in organization."""
    if status not in ("active", "disabled"):
        return False
    conn = get_db_connection()
    with conn:
        conn.execute("""
        UPDATE tenant_members SET status = ? WHERE tenant_id = ? AND user_id = ?
        """, (status, tenant_id, user_id))
    conn.close()
    return True


def remove_tenant_member(tenant_id: str, user_id: str) -> bool:
    """Remove member from organization."""
    conn = get_db_connection()
    with conn:
        conn.execute("DELETE FROM tenant_members WHERE tenant_id = ? AND user_id = ?", (tenant_id, user_id))
    conn.close()
    return True


def record_scan_ownership(scan_id: str, tenant_id: str, created_by: str) -> bool:
    """Bind a security scan run to its owner tenant organization."""
    conn = get_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            conn.execute("""
            INSERT OR REPLACE INTO scan_ownership (scan_id, tenant_id, created_by, created_at)
            VALUES (?, ?, ?, ?)
            """, (scan_id, tenant_id, created_by, now_iso))
        return True
    except Exception as exc:
        logger.error("Failed recording scan ownership: %s", exc)
        return False
    finally:
        conn.close()


def get_scan_ownership(scan_id: str) -> dict[str, Any] | None:
    """Get tenant ownership metadata for a scan run."""
    conn = get_db_connection()
    cur = conn.execute("SELECT * FROM scan_ownership WHERE scan_id = ?", (scan_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def list_scans_for_tenant(tenant_id: str) -> list[str]:
    """List all scan_ids belonging to a tenant."""
    conn = get_db_connection()
    cur = conn.execute("SELECT scan_id FROM scan_ownership WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,))
    scan_ids = [r["scan_id"] for r in cur.fetchall()]
    conn.close()
    return scan_ids


def log_audit_event(
    actor_user_id: str | None,
    actor_email: str | None,
    tenant_id: str | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    result: str = "success",
    ip_address: str | None = None,
    details: str | None = None,
) -> None:
    """Record an audit log entry for sensitive platform and scan operations."""
    event_id = f"audit_{uuid.uuid4().hex[:16]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
            INSERT INTO audit_logs (id, timestamp, actor_user_id, actor_email, tenant_id, action, resource_type, resource_id, result, ip_address, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (event_id, now_iso, actor_user_id, actor_email, tenant_id, action, resource_type, resource_id, result, ip_address, details))
    except Exception as exc:
        logger.error("Failed to write audit log: %s", exc)
    finally:
        conn.close()


def list_audit_logs(tenant_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    """Retrieve audit logs (filtered by tenant for ADMIN, all for SUPERADMIN)."""
    conn = get_db_connection()
    if tenant_id:
        cur = conn.execute("SELECT * FROM audit_logs WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ?", (tenant_id, limit))
    else:
        cur = conn.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows
