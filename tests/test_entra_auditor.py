from __future__ import annotations

import csv
import tempfile
import unittest
from datetime import date
from pathlib import Path

from src.entra_auditor import (
    audit_access,
    load_groups,
    load_memberships,
    load_role_assignments,
    load_users,
)


class EntraAuditorTests(unittest.TestCase):
    def write_csv(self, name: str, rows: list[dict[str, str]]) -> Path:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        path = Path(temp_dir.name) / name
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        return path

    def test_disabled_licensed_and_managerless_users_are_flagged(self) -> None:
        users_path = self.write_csv(
            "users.csv",
            [
                {
                    "id": "u1",
                    "userPrincipalName": "disabled@contoso.com",
                    "displayName": "Disabled User",
                    "userType": "Member",
                    "accountEnabled": "false",
                    "createdDateTime": "2024-01-01",
                    "signInActivityLastSignInDateTime": "2024-03-01",
                    "managerUserPrincipalName": "manager@contoso.com",
                    "assignedLicenses": "E3",
                    "department": "IT",
                    "jobTitle": "Analyst",
                },
                {
                    "id": "u2",
                    "userPrincipalName": "managerless@contoso.com",
                    "displayName": "Managerless User",
                    "userType": "Member",
                    "accountEnabled": "true",
                    "createdDateTime": "2026-01-01",
                    "signInActivityLastSignInDateTime": "2026-08-01",
                    "managerUserPrincipalName": "",
                    "assignedLicenses": "",
                    "department": "Finance",
                    "jobTitle": "Coordinator",
                },
            ],
        )

        findings = audit_access(load_users(users_path), [], [], [], today=date(2026, 8, 24))
        categories = {finding.category for finding in findings}

        self.assertIn("disabled-licensed-user", categories)
        self.assertIn("missing-manager", categories)

    def test_guest_in_sensitive_group_and_ownerless_group_are_flagged(self) -> None:
        users_path = self.write_csv(
            "users.csv",
            [
                {
                    "id": "u1",
                    "userPrincipalName": "guest#EXT#@contoso.onmicrosoft.com",
                    "displayName": "Guest User",
                    "userType": "Guest",
                    "accountEnabled": "true",
                    "createdDateTime": "2024-01-01",
                    "signInActivityLastSignInDateTime": "2024-03-01",
                    "managerUserPrincipalName": "",
                    "assignedLicenses": "",
                    "department": "External",
                    "jobTitle": "Contractor",
                }
            ],
        )
        groups_path = self.write_csv(
            "groups.csv",
            [
                {
                    "id": "g1",
                    "displayName": "Finance SharePoint Members",
                    "owners": "",
                    "sensitivityLabel": "Confidential",
                    "securityEnabled": "true",
                    "mailEnabled": "true",
                }
            ],
        )
        memberships_path = self.write_csv(
            "group_memberships.csv",
            [
                {
                    "groupId": "g1",
                    "memberId": "u1",
                    "memberUserPrincipalName": "guest#EXT#@contoso.onmicrosoft.com",
                    "memberType": "Guest",
                }
            ],
        )

        findings = audit_access(
            load_users(users_path),
            load_groups(groups_path),
            load_memberships(memberships_path),
            [],
            today=date(2026, 8, 24),
        )
        categories = {finding.category for finding in findings}

        self.assertIn("stale-guest-user", categories)
        self.assertIn("ownerless-group", categories)
        self.assertIn("guest-in-sensitive-group", categories)

    def test_privileged_roles_are_flagged(self) -> None:
        users_path = self.write_csv(
            "users.csv",
            [
                {
                    "id": "u1",
                    "userPrincipalName": "admin@contoso.com",
                    "displayName": "Admin User",
                    "userType": "Member",
                    "accountEnabled": "true",
                    "createdDateTime": "2024-01-01",
                    "signInActivityLastSignInDateTime": "2026-08-01",
                    "managerUserPrincipalName": "manager@contoso.com",
                    "assignedLicenses": "",
                    "department": "IT",
                    "jobTitle": "Admin",
                }
            ],
        )
        roles_path = self.write_csv(
            "role_assignments.csv",
            [
                {
                    "roleName": "Global Administrator",
                    "principalId": "u1",
                    "principalUserPrincipalName": "admin@contoso.com",
                    "assignmentType": "active",
                }
            ],
        )

        findings = audit_access(
            load_users(users_path),
            [],
            [],
            load_role_assignments(roles_path),
            today=date(2026, 8, 24),
        )

        self.assertIn("privileged-role-review", {finding.category for finding in findings})


if __name__ == "__main__":
    unittest.main()
