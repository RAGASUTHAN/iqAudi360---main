"""Comprehensive test suite for iqAudi360 Authentication, RBAC, and Multi-Tenancy."""

import json
import os
import unittest
from pathlib import Path
from flask import session

from strix.gui.app import create_app
from strix.gui.auth.db import (
    add_tenant_member,
    create_tenant,
    get_or_create_user,
    get_scan_ownership,
    get_tenant_membership,
    get_user_by_id,
    init_db,
    list_all_tenants,
    list_all_users,
    list_audit_logs,
    list_tenant_members,
    list_tenants_for_user,
    record_scan_ownership,
    remove_tenant_member,
    set_user_superadmin,
    update_tenant_member_role,
    update_user_status,
)
from strix.gui.auth.rbac import (
    ROLE_ADMIN,
    ROLE_CLIENT,
    ROLE_DEV,
    ROLE_SUPERADMIN,
    can_manage_role,
    has_permission,
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
)


class TestRBACPermissions(unittest.TestCase):
    """Test RBAC role permission mappings and hierarchy rules."""

    def test_superadmin_permissions(self):
        self.assertTrue(has_permission(ROLE_SUPERADMIN, PERM_PLATFORM_MANAGE))
        self.assertTrue(has_permission(ROLE_SUPERADMIN, PERM_ORG_MANAGE))
        self.assertTrue(has_permission(ROLE_SUPERADMIN, PERM_USER_MANAGE))
        self.assertTrue(has_permission(ROLE_SUPERADMIN, PERM_SCAN_CREATE))
        self.assertTrue(has_permission(ROLE_SUPERADMIN, PERM_SCAN_START))
        self.assertTrue(has_permission(ROLE_SUPERADMIN, PERM_SCAN_STOP))
        self.assertTrue(has_permission(ROLE_SUPERADMIN, PERM_LOGS_VIEW))
        self.assertTrue(has_permission(ROLE_SUPERADMIN, PERM_FINDINGS_VIEW))
        self.assertTrue(has_permission(ROLE_SUPERADMIN, PERM_REPORTS_VIEW))
        self.assertTrue(has_permission(ROLE_SUPERADMIN, PERM_REPORTS_DOWNLOAD))

    def test_admin_permissions(self):
        self.assertFalse(has_permission(ROLE_ADMIN, PERM_PLATFORM_MANAGE))
        self.assertTrue(has_permission(ROLE_ADMIN, PERM_ORG_MANAGE))
        self.assertTrue(has_permission(ROLE_ADMIN, PERM_USER_MANAGE))
        self.assertTrue(has_permission(ROLE_ADMIN, PERM_SCAN_CREATE))
        self.assertTrue(has_permission(ROLE_ADMIN, PERM_SCAN_START))
        self.assertTrue(has_permission(ROLE_ADMIN, PERM_SCAN_STOP))
        self.assertTrue(has_permission(ROLE_ADMIN, PERM_LOGS_VIEW))
        self.assertTrue(has_permission(ROLE_ADMIN, PERM_FINDINGS_VIEW))
        self.assertTrue(has_permission(ROLE_ADMIN, PERM_REPORTS_VIEW))

    def test_dev_permissions(self):
        self.assertFalse(has_permission(ROLE_DEV, PERM_PLATFORM_MANAGE))
        self.assertFalse(has_permission(ROLE_DEV, PERM_ORG_MANAGE))
        self.assertFalse(has_permission(ROLE_DEV, PERM_USER_MANAGE))
        self.assertTrue(has_permission(ROLE_DEV, PERM_SCAN_CREATE))
        self.assertTrue(has_permission(ROLE_DEV, PERM_SCAN_START))
        self.assertTrue(has_permission(ROLE_DEV, PERM_SCAN_STOP))
        self.assertTrue(has_permission(ROLE_DEV, PERM_LOGS_VIEW))
        self.assertTrue(has_permission(ROLE_DEV, PERM_FINDINGS_VIEW))
        self.assertTrue(has_permission(ROLE_DEV, PERM_REPORTS_VIEW))

    def test_client_permissions(self):
        self.assertFalse(has_permission(ROLE_CLIENT, PERM_PLATFORM_MANAGE))
        self.assertFalse(has_permission(ROLE_CLIENT, PERM_ORG_MANAGE))
        self.assertFalse(has_permission(ROLE_CLIENT, PERM_USER_MANAGE))
        self.assertFalse(has_permission(ROLE_CLIENT, PERM_SCAN_CREATE))
        self.assertFalse(has_permission(ROLE_CLIENT, PERM_SCAN_START))
        self.assertFalse(has_permission(ROLE_CLIENT, PERM_SCAN_STOP))
        self.assertFalse(has_permission(ROLE_CLIENT, PERM_LOGS_VIEW))
        self.assertTrue(has_permission(ROLE_CLIENT, PERM_FINDINGS_VIEW))
        self.assertTrue(has_permission(ROLE_CLIENT, PERM_REPORTS_VIEW))
        self.assertTrue(has_permission(ROLE_CLIENT, PERM_REPORTS_DOWNLOAD))

    def test_role_management_hierarchy(self):
        # Superadmin can manage anything
        self.assertTrue(can_manage_role(ROLE_SUPERADMIN, ROLE_SUPERADMIN))
        self.assertTrue(can_manage_role(ROLE_SUPERADMIN, ROLE_ADMIN))
        self.assertTrue(can_manage_role(ROLE_SUPERADMIN, ROLE_DEV))
        self.assertTrue(can_manage_role(ROLE_SUPERADMIN, ROLE_CLIENT))

        # Admin can ONLY manage DEV and CLIENT
        self.assertFalse(can_manage_role(ROLE_ADMIN, ROLE_SUPERADMIN))
        self.assertFalse(can_manage_role(ROLE_ADMIN, ROLE_ADMIN))
        self.assertTrue(can_manage_role(ROLE_ADMIN, ROLE_DEV))
        self.assertTrue(can_manage_role(ROLE_ADMIN, ROLE_CLIENT))

        # DEV and CLIENT cannot manage any roles
        self.assertFalse(can_manage_role(ROLE_DEV, ROLE_DEV))
        self.assertFalse(can_manage_role(ROLE_CLIENT, ROLE_CLIENT))


class TestMultiTenantAuthFlow(unittest.TestCase):
    """Test Flask Web Endpoints, Tenant Isolation, and RBAC Enforcement."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True

    def setUp(self):
        self.client = self.app.test_client()
        init_db()
        from strix.gui.auth.db import get_db_connection
        conn = get_db_connection()
        with conn:
            conn.execute("DELETE FROM scan_ownership")
            conn.execute("DELETE FROM audit_logs")
            conn.execute("DELETE FROM tenant_members")
            conn.execute("DELETE FROM tenants")
            conn.execute("DELETE FROM users")
        conn.close()

        # Seed test users
        # 1. Superadmin (user 1)
        self.superadmin = get_or_create_user("uid_super_01", "superadmin@iqaudi360.com", "Super Admin")
        set_user_superadmin(self.superadmin["user_id"], True)

        # 2. Org A Admin
        self.org_a = create_tenant("Org Alpha", self.superadmin["user_id"])
        self.admin_a = get_or_create_user("uid_admin_a", "admin@alpha.com", "Alice Admin")
        add_tenant_member(self.org_a["tenant_id"], self.admin_a["user_id"], ROLE_ADMIN)

        # 3. Org A Dev
        self.dev_a = get_or_create_user("uid_dev_a", "dev@alpha.com", "Dan Dev")
        add_tenant_member(self.org_a["tenant_id"], self.dev_a["user_id"], ROLE_DEV)

        # 4. Org A Client
        self.client_a = get_or_create_user("uid_client_a", "client@alpha.com", "Charlie Client")
        add_tenant_member(self.org_a["tenant_id"], self.client_a["user_id"], ROLE_CLIENT)

        # 5. Org B Admin
        self.org_b = create_tenant("Org Beta", self.superadmin["user_id"])
        self.admin_b = get_or_create_user("uid_admin_b", "admin@beta.com", "Bob Admin")
        add_tenant_member(self.org_b["tenant_id"], self.admin_b["user_id"], ROLE_ADMIN)

        # Seed Scans
        self.scan_a = "scan_alpha_101"
        record_scan_ownership(self.scan_a, self.org_a["tenant_id"], self.dev_a["user_id"])

        self.scan_b = "scan_beta_202"
        record_scan_ownership(self.scan_b, self.org_b["tenant_id"], self.admin_b["user_id"])

    def login_as(self, user, tenant_id=None):
        """Helper to establish test session."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = user["user_id"]
            if tenant_id:
                sess["active_tenant_id"] = tenant_id

    def test_unauthenticated_access_blocked(self):
        """Unauthenticated requests must receive 401 or redirect to /login."""
        # API request -> 401
        res = self.client.get("/api/scans/scan_alpha_101", headers={"Accept": "application/json"})
        self.assertEqual(res.status_code, 401)

        # Web view -> 302 to login
        res = self.client.get("/")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers["Location"])

    def test_client_cannot_start_scan(self):
        """CLIENT role must receive 403 when attempting to start a scan."""
        self.login_as(self.client_a, self.org_a["tenant_id"])
        res = self.client.post("/api/scans/start", json={
            "target": "example.com",
            "authorized": True
        })
        self.assertEqual(res.status_code, 403)

    def test_dev_can_start_scan_for_own_tenant(self):
        """DEV role can start scans for their active tenant."""
        self.login_as(self.dev_a, self.org_a["tenant_id"])
        # Validation error for missing authorized checkbox is 400, not 403
        res = self.client.post("/api/scans/start", json={
            "target": "example.com",
            "authorized": False
        })
        self.assertEqual(res.status_code, 400)

    def test_cross_tenant_scan_isolation(self):
        """User in Tenant A must receive 403 when requesting Tenant B's scan."""
        # Admin A tries to access Scan B belonging to Org B
        self.login_as(self.admin_a, self.org_a["tenant_id"])
        res = self.client.get(f"/api/scans/{self.scan_b}")
        self.assertEqual(res.status_code, 403)

        # Dev A tries to access Scan B
        self.login_as(self.dev_a, self.org_a["tenant_id"])
        res = self.client.get(f"/api/scans/{self.scan_b}")
        self.assertEqual(res.status_code, 403)

        # Client A tries to access Scan B
        self.login_as(self.client_a, self.org_a["tenant_id"])
        res = self.client.get(f"/api/scans/{self.scan_b}")
        self.assertEqual(res.status_code, 403)

    def test_superadmin_cross_tenant_access(self):
        """SUPERADMIN can access scans and resources across all tenants."""
        self.login_as(self.superadmin)
        res = self.client.get(f"/api/scans/{self.scan_a}")
        # Not 403 Forbidden (returns 200 or 404 scan-dir if mock id)
        self.assertNotEqual(res.status_code, 403)

        res = self.client.get(f"/api/scans/{self.scan_b}")
        self.assertNotEqual(res.status_code, 403)

    def test_admin_cannot_access_platform_settings(self):
        """ADMIN cannot access platform settings (SUPERADMIN only)."""
        self.login_as(self.admin_a, self.org_a["tenant_id"])
        res = self.client.get("/settings")
        self.assertEqual(res.status_code, 403)

    def test_admin_cannot_promote_to_superadmin(self):
        """ADMIN cannot grant SUPERADMIN privileges."""
        self.login_as(self.admin_a, self.org_a["tenant_id"])
        res = self.client.put(f"/api/admin/users/{self.admin_a['user_id']}/superadmin", json={
            "is_superadmin": True
        })
        self.assertEqual(res.status_code, 403)

    def test_tenant_switching(self):
        """User with multiple tenant memberships can switch context securely."""
        # Add Dev A to Org B as well
        add_tenant_member(self.org_b["tenant_id"], self.dev_a["user_id"], ROLE_DEV)

        self.login_as(self.dev_a, self.org_a["tenant_id"])
        res = self.client.post("/api/auth/switch-tenant", json={
            "tenant_id": self.org_b["tenant_id"]
        })
        self.assertEqual(res.status_code, 200)

        # But switching to an unassigned tenant returns 403
        org_c = create_tenant("Org Gamma", self.superadmin["user_id"])
        res = self.client.post("/api/auth/switch-tenant", json={
            "tenant_id": org_c["tenant_id"]
        })
        self.assertEqual(res.status_code, 403)

    def test_admin_can_manage_dev_and_client(self):
        """ADMIN can invite, update, and remove DEV and CLIENT members in own tenant."""
        self.login_as(self.admin_a, self.org_a["tenant_id"])

        # 1. Invite new DEV member
        res = self.client.post(f"/api/organizations/{self.org_a['tenant_id']}/members", json={
            "email": "newdev@alpha.com",
            "role": "DEV"
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        new_user_id = data["membership"]["user_id"]

        # 2. Update role to CLIENT
        res = self.client.put(f"/api/organizations/{self.org_a['tenant_id']}/members/{new_user_id}", json={
            "role": "CLIENT"
        })
        self.assertEqual(res.status_code, 200)

        # 3. Admin attempting to assign ADMIN role (disallowed for non-superadmin)
        res = self.client.put(f"/api/organizations/{self.org_a['tenant_id']}/members/{new_user_id}", json={
            "role": "ADMIN"
        })
        self.assertEqual(res.status_code, 403)

        # 4. Remove member
        res = self.client.delete(f"/api/organizations/{self.org_a['tenant_id']}/members/{new_user_id}")
        self.assertEqual(res.status_code, 200)

    def test_dev_cannot_manage_members(self):
        """DEV cannot add or remove members from organization."""
        self.login_as(self.dev_a, self.org_a["tenant_id"])
        res = self.client.post(f"/api/organizations/{self.org_a['tenant_id']}/members", json={
            "email": "intruder@alpha.com",
            "role": "DEV"
        })
        self.assertEqual(res.status_code, 403)

    def test_audit_logs_recording(self):
        """Audit logs record actions and are accessible to ADMIN and SUPERADMIN."""
        self.login_as(self.superadmin)
        res = self.client.get("/api/audit-logs")
        self.assertEqual(res.status_code, 200)
        logs = res.get_json()["logs"]
        self.assertIsInstance(logs, list)

    def test_api_auth_me_endpoint(self):
        """Endpoint /api/auth/me returns accurate profile and active context."""
        self.login_as(self.dev_a, self.org_a["tenant_id"])
        res = self.client.get("/api/auth/me")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["user"]["email"], "dev@alpha.com")
        self.assertEqual(data["current_role"], "DEV")
        self.assertEqual(data["current_tenant"]["tenant_id"], self.org_a["tenant_id"])
        self.assertFalse(data["is_superadmin"])

    def test_authenticated_user_redirected_from_login_and_register(self):
        """Authenticated users visiting /login or /register are redirected to dashboard."""
        self.login_as(self.dev_a, self.org_a["tenant_id"])

        res = self.client.get("/login")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/", res.headers["Location"])

        res = self.client.get("/register")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/", res.headers["Location"])

    def test_unauthenticated_login_page_renders_cleanly(self):
        """Unauthenticated user receives login page with Firebase configuration."""
        res = self.client.get("/login")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"iqaudi360", res.data)
        self.assertIn(b"firebase-auth.js", res.data)

    def test_unauthenticated_register_page_renders_cleanly(self):
        """Unauthenticated user receives register page with Firebase configuration."""
        res = self.client.get("/register")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"iqaudi360", res.data)
        self.assertIn(b"firebase-auth.js", res.data)

    def test_logout_clears_session(self):
        """Logout endpoint clears session and redirects to /login."""
        self.login_as(self.dev_a, self.org_a["tenant_id"])
        res = self.client.get("/logout")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers["Location"])

        # Subsequent protected route access requires login
        res = self.client.get("/scans")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers["Location"])


if __name__ == "__main__":
    unittest.main()
