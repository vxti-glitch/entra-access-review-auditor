from __future__ import annotations

import csv
import copy
import tempfile
import unittest
from datetime import date
from pathlib import Path

from src.entra_auditor import (
    load_config,
    load_groups,
    load_memberships,
    load_role_assignments,
    load_users,
    review_access,
)


TODAY = date(2026, 8, 24)


class EntraCandidateTests(unittest.TestCase):
    def write_csv(self, name: str, rows: list[dict[str, str]]) -> Path:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        path = Path(temp_dir.name) / name
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        return path

    def user(self, **updates: str) -> dict[str, str]:
        row = {
            "id": "u1", "userPrincipalName": "person@example.test",
            "displayName": "Example Person", "userType": "Member",
            "accountEnabled": "true", "createdDateTime": "2024-01-01",
            "signInActivityLastSignInDateTime": "2026-08-01",
            "managerUserPrincipalName": "manager@example.test", "assignedLicenses": "",
            "department": "Operations", "jobTitle": "Analyst",
        }
        row.update(updates)
        return row

    def config(self) -> dict:
        return copy.deepcopy(load_config())

    def test_unknown_signin_is_not_stale(self) -> None:
        path = self.write_csv("users.csv", [self.user(signInActivityLastSignInDateTime="")])
        candidates = review_access(load_users(path), [], [], [], config=self.config(), today=TODAY)
        categories = {item.category for item in candidates}
        self.assertIn("sign-in-data-unknown", categories)
        self.assertNotIn("stale-member-candidate", categories)
        self.assertEqual(next(item.sign_in_state for item in candidates if item.category == "sign-in-data-unknown"), "unknown")

    def test_owner_unavailable_is_distinct_from_confirmed_ownerless(self) -> None:
        groups = self.write_csv("groups.csv", [
            {"id": "g1", "displayName": "Unavailable", "owners": "", "ownersDataStatus": "unavailable", "sensitivityLabel": "General"},
            {"id": "g2", "displayName": "Confirmed empty", "owners": "", "ownersDataStatus": "available", "sensitivityLabel": "General"},
        ])
        candidates = review_access([], load_groups(groups), [], [], config=self.config(), today=TODAY)
        by_principal = {item.principal: item.category for item in candidates}
        self.assertEqual(by_principal["Unavailable"], "group-owner-data-unavailable")
        self.assertEqual(by_principal["Confirmed empty"], "confirmed-ownerless-group-candidate")

    def test_svc_substring_does_not_exclude_a_human_by_default(self) -> None:
        path = self.write_csv("users.csv", [self.user(id="u-human", userPrincipalName="vasco.svcera@example.test", displayName="Vasco Svcera", managerUserPrincipalName="", signInActivityLastSignInDateTime="2025-01-01")])
        categories = {item.category for item in review_access(load_users(path), [], [], [], config=self.config(), today=TODAY)}
        self.assertIn("stale-member-candidate", categories)
        self.assertIn("missing-manager-candidate", categories)

    def test_explicit_service_account_is_excluded_from_human_rules(self) -> None:
        path = self.write_csv("users.csv", [self.user(id="u-004", userPrincipalName="svc.backup@contoso.com", managerUserPrincipalName="", signInActivityLastSignInDateTime="2025-01-01")])
        categories = {item.category for item in review_access(load_users(path), [], [], [], config=self.config(), today=TODAY)}
        self.assertNotIn("stale-member-candidate", categories)
        self.assertNotIn("missing-manager-candidate", categories)

    def test_custom_and_non_english_role_names_require_configuration(self) -> None:
        roles = self.write_csv("roles.csv", [
            {"roleName": "Administrateur général", "principalId": "u1", "principalUserPrincipalName": "one@example.test"},
            {"roleName": "Tenant Custodian", "principalId": "u2", "principalUserPrincipalName": "two@example.test"},
        ])
        loaded = load_role_assignments(roles)
        self.assertEqual(review_access([], [], [], loaded, config=self.config(), today=TODAY), [])
        configured = self.config()
        configured["privileged_roles"]["identifiers"].append("Administrateur général")
        configured["privileged_roles"]["identifiers"].append("Tenant Custodian")
        candidates = review_access([], [], [], loaded, config=configured, today=TODAY)
        self.assertEqual(len(candidates), 2)
        self.assertTrue(all(item.classification == "heuristic" for item in candidates))

    def test_configurable_threshold_changes_candidate_result(self) -> None:
        path = self.write_csv("users.csv", [self.user(signInActivityLastSignInDateTime="2026-06-01")])
        config = self.config()
        config["stale_days"] = 90
        self.assertNotIn("stale-member-candidate", {item.category for item in review_access(load_users(path), [], [], [], config=config, today=TODAY)})
        config["stale_days"] = 30
        self.assertIn("stale-member-candidate", {item.category for item in review_access(load_users(path), [], [], [], config=config, today=TODAY)})

    def test_ambiguous_membership_and_role_records_are_review_candidates(self) -> None:
        memberships = self.write_csv("memberships.csv", [{"groupId": "missing", "memberId": "missing", "memberUserPrincipalName": "ambiguous@example.test", "memberType": "Member"}])
        roles = self.write_csv("roles.csv", [{"roleName": "", "principalId": "", "principalUserPrincipalName": "", "assignmentType": ""}])
        candidates = review_access([], [], load_memberships(memberships), load_role_assignments(roles), config=self.config(), today=TODAY)
        self.assertEqual({item.category for item in candidates}, {"ambiguous-membership-record", "ambiguous-role-record"})

    def test_sensitive_group_and_role_candidates_expose_triggered_rules(self) -> None:
        users = self.write_csv("users.csv", [self.user(id="u1", userType="Guest")])
        groups = self.write_csv("groups.csv", [{"id": "g-fin", "displayName": "Finance Team", "owners": "owner@example.test", "ownersDataStatus": "available", "sensitivityLabel": "General"}])
        memberships = self.write_csv("memberships.csv", [{"groupId": "g-fin", "memberId": "u1", "memberUserPrincipalName": "person@example.test", "memberType": "Guest"}])
        roles = self.write_csv("roles.csv", [{"roleName": "Global Administrator", "principalId": "u1", "principalUserPrincipalName": "person@example.test", "assignmentType": "eligible"}])
        candidates = review_access(load_users(users), load_groups(groups), load_memberships(memberships), load_role_assignments(roles), config=self.config(), today=TODAY)
        heuristic = [item for item in candidates if item.classification == "heuristic"]
        self.assertEqual(len(heuristic), 2)
        self.assertTrue(all(item.triggered_rule for item in heuristic))


if __name__ == "__main__":
    unittest.main()
