"""Offline Microsoft Entra access review auditor."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Iterable


PRIVILEGED_ROLE_KEYWORDS = (
    "administrator",
    "global admin",
    "privileged",
    "security admin",
)
SENSITIVE_GROUP_KEYWORDS = (
    "admin",
    "break glass",
    "finance",
    "hr",
    "payroll",
    "privileged",
)


@dataclass(frozen=True)
class UserRecord:
    id: str
    upn: str
    display_name: str
    user_type: str
    account_enabled: bool
    created_date: date | None
    last_signin_date: date | None
    manager_upn: str
    assigned_licenses: tuple[str, ...]
    department: str = ""
    job_title: str = ""


@dataclass(frozen=True)
class GroupRecord:
    id: str
    display_name: str
    owners: tuple[str, ...]
    sensitivity_label: str
    security_enabled: bool = False
    mail_enabled: bool = False


@dataclass(frozen=True)
class MembershipRecord:
    group_id: str
    member_id: str
    member_upn: str
    member_type: str


@dataclass(frozen=True)
class RoleAssignment:
    role_name: str
    principal_id: str
    principal_upn: str
    assignment_type: str = ""


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    principal: str
    detail: str
    recommendation: str


def parse_bool(value: str) -> bool:
    return value.strip().lower() in {"true", "1", "yes", "y"}


def parse_date(value: str) -> date | None:
    value = value.strip()
    if not value:
        return None
    cleaned = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(cleaned).date()
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y"):
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    return None


def split_multi(value: str) -> tuple[str, ...]:
    if not value or value.strip().lower() in {"none", "null", "n/a"}:
        return tuple()
    parts = []
    for raw in value.replace("|", ";").replace(",", ";").split(";"):
        item = raw.strip()
        if item:
            parts.append(item)
    return tuple(parts)


def load_rows(path: Path, required_columns: Iterable[str]) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError(f"{path} is empty or missing headers.")
        header_map = {header.strip().lower(): header for header in reader.fieldnames}
        missing = [name for name in required_columns if name.lower() not in header_map]
        if missing:
            raise ValueError(f"{path} missing required columns: {', '.join(missing)}")

        rows = []
        for row in reader:
            normalized = {
                canonical: (row.get(original, "") or "").strip()
                for canonical, original in header_map.items()
            }
            rows.append(normalized)
        return rows


def load_users(path: Path) -> list[UserRecord]:
    rows = load_rows(
        path,
        (
            "id",
            "userPrincipalName",
            "displayName",
            "userType",
            "accountEnabled",
            "createdDateTime",
            "signInActivityLastSignInDateTime",
            "managerUserPrincipalName",
            "assignedLicenses",
        ),
    )
    users = []
    for row in rows:
        users.append(
            UserRecord(
                id=row["id"],
                upn=row["userprincipalname"],
                display_name=row["displayname"],
                user_type=row["usertype"],
                account_enabled=parse_bool(row["accountenabled"]),
                created_date=parse_date(row["createddatetime"]),
                last_signin_date=parse_date(row["signinactivitylastsignindatetime"]),
                manager_upn=row["manageruserprincipalname"],
                assigned_licenses=split_multi(row["assignedlicenses"]),
                department=row.get("department", ""),
                job_title=row.get("jobtitle", ""),
            )
        )
    return users


def load_groups(path: Path) -> list[GroupRecord]:
    rows = load_rows(path, ("id", "displayName", "owners", "sensitivityLabel"))
    groups = []
    for row in rows:
        groups.append(
            GroupRecord(
                id=row["id"],
                display_name=row["displayname"],
                owners=split_multi(row["owners"]),
                sensitivity_label=row["sensitivitylabel"],
                security_enabled=parse_bool(row.get("securityenabled", "")),
                mail_enabled=parse_bool(row.get("mailenabled", "")),
            )
        )
    return groups


def load_memberships(path: Path) -> list[MembershipRecord]:
    rows = load_rows(path, ("groupId", "memberId", "memberUserPrincipalName", "memberType"))
    return [
        MembershipRecord(
            group_id=row["groupid"],
            member_id=row["memberid"],
            member_upn=row["memberuserprincipalname"],
            member_type=row["membertype"],
        )
        for row in rows
    ]


def load_role_assignments(path: Path | None) -> list[RoleAssignment]:
    if not path:
        return []
    rows = load_rows(path, ("roleName", "principalId", "principalUserPrincipalName"))
    return [
        RoleAssignment(
            role_name=row["rolename"],
            principal_id=row["principalid"],
            principal_upn=row["principaluserprincipalname"],
            assignment_type=row.get("assignmenttype", ""),
        )
        for row in rows
    ]


def is_service_account(user: UserRecord) -> bool:
    probe = " ".join([user.upn, user.display_name, user.job_title]).lower()
    return "svc" in probe or "service account" in probe


def is_sensitive_group(group: GroupRecord) -> bool:
    probe = " ".join([group.display_name, group.sensitivity_label]).lower()
    return any(keyword in probe for keyword in SENSITIVE_GROUP_KEYWORDS)


def is_privileged_role(role_name: str) -> bool:
    normalized = role_name.lower()
    return any(keyword in normalized for keyword in PRIVILEGED_ROLE_KEYWORDS)


def audit_access(
    users: list[UserRecord],
    groups: list[GroupRecord],
    memberships: list[MembershipRecord],
    role_assignments: list[RoleAssignment],
    *,
    today: date | None = None,
    stale_days: int = 90,
    guest_stale_days: int = 30,
) -> list[Finding]:
    today = today or date.today()
    stale_cutoff = today - timedelta(days=stale_days)
    guest_cutoff = today - timedelta(days=guest_stale_days)
    users_by_id = {user.id: user for user in users}
    groups_by_id = {group.id: group for group in groups}
    findings: list[Finding] = []

    for user in users:
        display = user.upn or user.display_name or user.id
        if not user.account_enabled and user.assigned_licenses:
            findings.append(
                Finding(
                    "medium",
                    "disabled-licensed-user",
                    display,
                    "Disabled account still has assigned licenses.",
                    "Review license assignment and remove unused licenses if no exception exists.",
                )
            )

        no_recent_signin = user.last_signin_date is None or user.last_signin_date < stale_cutoff
        created_before_cutoff = user.created_date is None or user.created_date < stale_cutoff
        if user.account_enabled and user.user_type.lower() == "member" and no_recent_signin and created_before_cutoff and not is_service_account(user):
            findings.append(
                Finding(
                    "medium",
                    "stale-enabled-user",
                    display,
                    f"Enabled member account has no sign-in within {stale_days} days.",
                    "Validate employment status and disable or document an exception.",
                )
            )

        guest_stale = user.last_signin_date is None or user.last_signin_date < guest_cutoff
        if user.account_enabled and user.user_type.lower() == "guest" and guest_stale:
            findings.append(
                Finding(
                    "high",
                    "stale-guest-user",
                    display,
                    f"Guest account has no sign-in within {guest_stale_days} days.",
                    "Ask the sponsor to approve continued access or remove the guest.",
                )
            )

        if user.account_enabled and user.user_type.lower() == "member" and not user.manager_upn and not is_service_account(user):
            findings.append(
                Finding(
                    "low",
                    "missing-manager",
                    display,
                    "Enabled member account has no manager value.",
                    "Update the manager attribute to support approvals and access reviews.",
                )
            )

    for group in groups:
        display = group.display_name or group.id
        if not group.owners:
            severity = "high" if is_sensitive_group(group) else "medium"
            findings.append(
                Finding(
                    severity,
                    "ownerless-group",
                    display,
                    "Group does not have an owner recorded in the export.",
                    "Assign a business owner before the next access review.",
                )
            )

    for membership in memberships:
        user = users_by_id.get(membership.member_id)
        group = groups_by_id.get(membership.group_id)
        if not user or not group:
            continue
        if user.user_type.lower() == "guest" and is_sensitive_group(group):
            findings.append(
                Finding(
                    "high",
                    "guest-in-sensitive-group",
                    user.upn,
                    f"Guest has membership in sensitive group '{group.display_name}'.",
                    "Require owner approval or remove the guest from the group.",
                )
            )

    for assignment in role_assignments:
        role_display = assignment.role_name or "Unknown role"
        user = users_by_id.get(assignment.principal_id)
        if not is_privileged_role(role_display):
            continue
        severity = "high"
        detail = f"Principal has {assignment.assignment_type or 'unknown'} assignment to '{role_display}'."
        if user and not user.account_enabled:
            detail += " The principal account is disabled."
        findings.append(
            Finding(
                severity,
                "privileged-role-review",
                assignment.principal_upn or assignment.principal_id,
                detail,
                "Confirm the role assignment is still required and covered by an access review.",
            )
        )

    return findings


def build_payload(
    users: list[UserRecord],
    groups: list[GroupRecord],
    memberships: list[MembershipRecord],
    role_assignments: list[RoleAssignment],
    findings: list[Finding],
) -> dict[str, object]:
    return {
        "summary": {
            "users": len(users),
            "groups": len(groups),
            "memberships": len(memberships),
            "role_assignments": len(role_assignments),
            "findings": len(findings),
            "findings_by_severity": dict(Counter(finding.severity for finding in findings)),
            "findings_by_category": dict(Counter(finding.category for finding in findings)),
        },
        "findings": [asdict(finding) for finding in findings],
    }


def render_markdown(payload: dict[str, object]) -> str:
    summary = payload["summary"]
    findings = payload["findings"]
    lines = [
        "# Entra Access Review Findings",
        "",
        "## Summary",
        "",
        f"- Users reviewed: {summary['users']}",
        f"- Groups reviewed: {summary['groups']}",
        f"- Memberships reviewed: {summary['memberships']}",
        f"- Role assignments reviewed: {summary['role_assignments']}",
        f"- Findings: {summary['findings']}",
        "",
        "## Findings",
        "",
    ]

    if not findings:
        lines.append("No review candidates found.")
    else:
        lines.extend(["| Severity | Category | Principal | Detail | Recommendation |", "| --- | --- | --- | --- | --- |"])
        for finding in findings:
            lines.append(
                "| {severity} | {category} | {principal} | {detail} | {recommendation} |".format(
                    **finding
                )
            )

    lines.extend(
        [
            "",
            "## Suggested Review Cadence",
            "",
            "- Review privileged roles monthly.",
            "- Review guest access monthly or quarterly depending on risk.",
            "- Review ownerless and sensitive groups before major audits.",
            "- Track accepted exceptions in a ticket or change record.",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(payload: dict[str, object], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "access-review-findings.json").write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8",
    )
    (output_dir / "access-review-findings.md").write_text(
        render_markdown(payload),
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit exported Entra ID data for access review candidates.")
    parser.add_argument("--users", required=True, type=Path, help="Path to users.csv export.")
    parser.add_argument("--groups", required=True, type=Path, help="Path to groups.csv export.")
    parser.add_argument("--memberships", required=True, type=Path, help="Path to group_memberships.csv export.")
    parser.add_argument("--roles", type=Path, help="Optional path to role_assignments.csv export.")
    parser.add_argument("--out", default=Path("reports"), type=Path, help="Output directory.")
    parser.add_argument("--stale-days", default=90, type=int, help="Member user stale sign-in threshold.")
    parser.add_argument("--guest-stale-days", default=30, type=int, help="Guest stale sign-in threshold.")
    parser.add_argument("--fail-on-high", action="store_true", help="Exit with code 1 when high severity findings exist.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    users = load_users(args.users)
    groups = load_groups(args.groups)
    memberships = load_memberships(args.memberships)
    roles = load_role_assignments(args.roles)
    findings = audit_access(
        users,
        groups,
        memberships,
        roles,
        stale_days=args.stale_days,
        guest_stale_days=args.guest_stale_days,
    )
    payload = build_payload(users, groups, memberships, roles, findings)
    write_outputs(payload, args.out)
    high_count = sum(1 for finding in findings if finding.severity == "high")
    print(f"Reviewed {len(users)} users, {len(groups)} groups, {len(memberships)} memberships.")
    print(f"Findings: {len(findings)} total, {high_count} high.")
    print(f"Output written to {args.out.resolve()}")
    return 1 if args.fail_on_high and high_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
