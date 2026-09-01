"""Offline Microsoft Entra access-review candidate helper."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Iterable


DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "review-rules.json"
OWNER_DATA_STATES = {"available", "unavailable"}


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
    owners_data_status: str
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
class ReviewCandidate:
    priority: str
    category: str
    principal: str
    sign_in_state: str
    classification: str
    triggered_rule: str
    detail: str
    next_step: str


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
        return [
            {
                canonical: (row.get(original, "") or "").strip()
                for canonical, original in header_map.items()
            }
            for row in reader
        ]


def load_users(path: Path) -> list[UserRecord]:
    rows = load_rows(
        path,
        (
            "id", "userPrincipalName", "displayName", "userType",
            "accountEnabled", "createdDateTime", "signInActivityLastSignInDateTime",
            "managerUserPrincipalName", "assignedLicenses",
        ),
    )
    return [
        UserRecord(
            id=row["id"], upn=row["userprincipalname"], display_name=row["displayname"],
            user_type=row["usertype"], account_enabled=parse_bool(row["accountenabled"]),
            created_date=parse_date(row["createddatetime"]),
            last_signin_date=parse_date(row["signinactivitylastsignindatetime"]),
            manager_upn=row["manageruserprincipalname"],
            assigned_licenses=split_multi(row["assignedlicenses"]),
            department=row.get("department", ""), job_title=row.get("jobtitle", ""),
        )
        for row in rows
    ]


def load_groups(path: Path) -> list[GroupRecord]:
    rows = load_rows(path, ("id", "displayName", "owners", "sensitivityLabel"))
    groups = []
    for row in rows:
        owner_status = row.get("ownersdatastatus", "unavailable").casefold()
        if owner_status not in OWNER_DATA_STATES:
            owner_status = "unavailable"
        groups.append(
            GroupRecord(
                id=row["id"], display_name=row["displayname"], owners=split_multi(row["owners"]),
                owners_data_status=owner_status, sensitivity_label=row["sensitivitylabel"],
                security_enabled=parse_bool(row.get("securityenabled", "")),
                mail_enabled=parse_bool(row.get("mailenabled", "")),
            )
        )
    return groups


def load_memberships(path: Path) -> list[MembershipRecord]:
    rows = load_rows(path, ("groupId", "memberId", "memberUserPrincipalName", "memberType"))
    return [MembershipRecord(row["groupid"], row["memberid"], row["memberuserprincipalname"], row["membertype"]) for row in rows]


def load_role_assignments(path: Path | None) -> list[RoleAssignment]:
    if not path:
        return []
    rows = load_rows(path, ("roleName", "principalId", "principalUserPrincipalName"))
    return [RoleAssignment(row["rolename"], row["principalid"], row["principaluserprincipalname"], row.get("assignmenttype", "")) for row in rows]


def load_config(path: Path = DEFAULT_CONFIG) -> dict:
    config = json.loads(path.read_text(encoding="utf-8"))
    for key in ("stale_days", "guest_stale_days"):
        if not isinstance(config.get(key), int) or config[key] < 1:
            raise ValueError(f"Configuration '{key}' must be a positive integer.")
    for key in ("sensitive_groups", "privileged_roles", "service_accounts"):
        if not isinstance(config.get(key), dict):
            raise ValueError(f"Configuration '{key}' must be an object.")
    return config


def sign_in_state(user: UserRecord, cutoff: date) -> str:
    if user.last_signin_date is None:
        return "unknown"
    return "known_stale" if user.last_signin_date < cutoff else "known_recent"


def _configured_match(values: Iterable[str], rule: dict, prefix: str) -> str | None:
    value_list = [value for value in values if value]
    normalized_values = [value.casefold() for value in value_list]
    for identifier in rule.get("identifiers", []):
        if identifier.casefold() in normalized_values:
            return f"{prefix}.identifier:{identifier}"
    probe = " | ".join(value_list)
    for pattern in rule.get("patterns", []):
        if re.search(pattern, probe, flags=re.IGNORECASE):
            return f"{prefix}.pattern:{pattern}"
    return None


def service_account_rule(user: UserRecord, config: dict) -> str | None:
    rule = config["service_accounts"]
    match = _configured_match([user.id, user.upn], {"identifiers": rule.get("identifiers", [])}, "service_account")
    if match:
        return match
    return _configured_match([user.upn, user.display_name, user.job_title], {"patterns": rule.get("patterns", [])}, "service_account")


def sensitive_group_rule(group: GroupRecord, config: dict) -> str | None:
    return _configured_match([group.id, group.display_name, group.sensitivity_label], config["sensitive_groups"], "sensitive_group")


def privileged_role_rule(role: RoleAssignment, config: dict) -> str | None:
    return _configured_match([role.role_name], config["privileged_roles"], "privileged_role")


def candidate(priority: str, category: str, principal: str, detail: str, next_step: str, *, rule: str, sign_in: str = "unknown", classification: str = "direct") -> ReviewCandidate:
    return ReviewCandidate(priority, category, principal, sign_in, classification, rule, detail, next_step)


def review_access(
    users: list[UserRecord], groups: list[GroupRecord], memberships: list[MembershipRecord],
    role_assignments: list[RoleAssignment], *, config: dict | None = None,
    today: date | None = None,
) -> list[ReviewCandidate]:
    config = config or load_config()
    today = today or date.today()
    member_cutoff = today - timedelta(days=config["stale_days"])
    guest_cutoff = today - timedelta(days=config["guest_stale_days"])
    users_by_id = {user.id: user for user in users}
    groups_by_id = {group.id: group for group in groups}
    candidates: list[ReviewCandidate] = []

    for user in users:
        display = user.upn or user.display_name or user.id or "incomplete-user-record"
        service_rule = service_account_rule(user, config)
        cutoff = guest_cutoff if user.user_type.casefold() == "guest" else member_cutoff
        state = sign_in_state(user, cutoff)
        if not user.account_enabled and user.assigned_licenses:
            candidates.append(candidate("medium", "disabled-licensed-user", display, "The export shows a disabled account with assigned licenses.", "Ask an authorized license owner to confirm whether an exception or removal is appropriate.", sign_in=state, rule="accountEnabled=false AND assignedLicenses not empty"))
        if user.account_enabled and user.user_type.casefold() in {"member", "guest"}:
            if state == "unknown":
                candidates.append(candidate("review", "sign-in-data-unknown", display, "The export does not contain a parseable last sign-in date; inactivity cannot be determined.", "Confirm export permissions and coverage or review this identity manually.", sign_in=state, rule="lastSignInDateTime missing_or_unparseable"))
            elif state == "known_stale" and not service_rule:
                guest = user.user_type.casefold() == "guest"
                threshold = config["guest_stale_days"] if guest else config["stale_days"]
                candidates.append(candidate("high" if guest else "medium", "stale-guest-candidate" if guest else "stale-member-candidate", display, f"The recorded last sign-in is older than the configured {threshold}-day threshold.", "An authorized owner or IAM reviewer must confirm context and decide whether access changes are appropriate.", sign_in=state, rule=f"lastSignInDateTime < today-{threshold}d"))
        if user.account_enabled and user.user_type.casefold() == "member" and not user.manager_upn and not service_rule:
            candidates.append(candidate("low", "missing-manager-candidate", display, "The export has no manager value and the identity is not an explicitly configured service account.", "Determine the account type and responsible owner; do not infer employment status from this field alone.", sign_in=state, rule="manager empty AND no explicit service-account rule"))

    for group in groups:
        display = group.display_name or group.id or "incomplete-group-record"
        sensitive_rule = sensitive_group_rule(group, config)
        if group.owners_data_status == "unavailable":
            candidates.append(candidate("review", "group-owner-data-unavailable", display, "Owner export coverage is unavailable, so ownerless status cannot be determined.", "Obtain an owner-inclusive export or ask an authorized group administrator to review.", rule="ownersDataStatus=unavailable"))
        elif not group.owners:
            candidates.append(candidate("high" if sensitive_rule else "medium", "confirmed-ownerless-group-candidate", display, "Owner data was available and no owner was recorded.", "An authorized group administrator must confirm ownership and remediation.", classification="heuristic" if sensitive_rule else "direct", rule=sensitive_rule or "ownersDataStatus=available AND owners empty"))

    for membership in memberships:
        user, group = users_by_id.get(membership.member_id), groups_by_id.get(membership.group_id)
        if not user or not group:
            candidates.append(candidate("review", "ambiguous-membership-record", membership.member_upn or membership.member_id or membership.group_id, "The membership could not be joined to both a user and group export record.", "Correct export scope or identifiers before drawing an access conclusion.", rule="membership join missing user_or_group"))
            continue
        sensitive_rule = sensitive_group_rule(group, config)
        if user.user_type.casefold() == "guest" and sensitive_rule:
            candidates.append(candidate("high", "guest-sensitive-group-candidate", user.upn or user.id, f"A guest is listed in group '{group.display_name}', which matched a configured sensitive-group heuristic.", "The authorized group owner or IAM reviewer must decide whether membership is appropriate.", sign_in=sign_in_state(user, guest_cutoff), classification="heuristic", rule=sensitive_rule))

    for assignment in role_assignments:
        if not assignment.role_name or not (assignment.principal_id or assignment.principal_upn):
            candidates.append(candidate("review", "ambiguous-role-record", assignment.principal_upn or assignment.principal_id or "incomplete-role-record", "The role assignment is missing a role name or principal identifier.", "Correct the export before classifying the assignment.", rule="roleName_or_principal missing"))
            continue
        role_rule = privileged_role_rule(assignment, config)
        if not role_rule:
            continue
        user = users_by_id.get(assignment.principal_id)
        detail = f"The role name '{assignment.role_name}' matched a configured privileged-role heuristic."
        if user and not user.account_enabled:
            detail += " The exported principal account is disabled."
        candidates.append(candidate("high", "privileged-role-review-candidate", assignment.principal_upn or assignment.principal_id, detail, "An authorized role owner or IAM reviewer must confirm necessity and assignment state.", sign_in=sign_in_state(user, member_cutoff) if user else "unknown", classification="heuristic", rule=role_rule))
    return candidates


audit_access = review_access


def build_payload(users: list[UserRecord], groups: list[GroupRecord], memberships: list[MembershipRecord], role_assignments: list[RoleAssignment], candidates: list[ReviewCandidate], config: dict) -> dict[str, object]:
    return {
        "decision_boundary": "Candidates require a decision by an authorized owner or IAM reviewer.",
        "configuration": config,
        "summary": {
            "users": len(users), "groups": len(groups), "memberships": len(memberships),
            "role_assignments": len(role_assignments), "candidates": len(candidates),
            "candidates_by_priority": dict(Counter(item.priority for item in candidates)),
            "candidates_by_category": dict(Counter(item.category for item in candidates)),
        },
        "candidates": [asdict(item) for item in candidates],
    }


def render_markdown(payload: dict[str, object]) -> str:
    summary, rows = payload["summary"], payload["candidates"]
    lines = [
        "# Entra Access-Review Candidates", "",
        "> Candidate helper output, not an audit conclusion. Final decisions belong to an authorized owner or IAM reviewer.", "",
        "## Summary", "", f"- Users parsed: {summary['users']}", f"- Groups parsed: {summary['groups']}",
        f"- Memberships parsed: {summary['memberships']}", f"- Role assignments parsed: {summary['role_assignments']}",
        f"- Candidates: {summary['candidates']}", "", "## Candidates", "",
    ]
    if not rows:
        lines.append("No candidates matched the configured rules. This is not proof that access is appropriate.")
    else:
        lines.extend(["| Priority | Category | Principal | Sign-in state | Classification | Triggered rule | Detail | Next step |", "| --- | --- | --- | --- | --- | --- | --- | --- |"])
        for row in rows:
            lines.append("| {priority} | {category} | {principal} | {sign_in_state} | {classification} | `{triggered_rule}` | {detail} | {next_step} |".format(**row))
    return "\n".join(lines) + "\n"


def write_outputs(payload: dict[str, object], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "access-review-candidates.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (output_dir / "access-review-candidates.md").write_text(render_markdown(payload), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare cautious review candidates from exported Microsoft Entra ID data.")
    parser.add_argument("--users", required=True, type=Path)
    parser.add_argument("--groups", required=True, type=Path)
    parser.add_argument("--memberships", required=True, type=Path)
    parser.add_argument("--roles", type=Path)
    parser.add_argument("--config", default=DEFAULT_CONFIG, type=Path)
    parser.add_argument("--out", default=Path("reports"), type=Path)
    parser.add_argument("--fail-on-high", action="store_true", help="Exit 1 when high-priority candidates exist; this does not establish risk.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_config(args.config)
    users, groups = load_users(args.users), load_groups(args.groups)
    memberships, roles = load_memberships(args.memberships), load_role_assignments(args.roles)
    candidates = review_access(users, groups, memberships, roles, config=config)
    payload = build_payload(users, groups, memberships, roles, candidates, config)
    write_outputs(payload, args.out)
    high_count = sum(1 for item in candidates if item.priority == "high")
    print(f"Parsed {len(users)} users, {len(groups)} groups, and {len(memberships)} memberships.")
    print(f"Candidates: {len(candidates)} total, {high_count} high priority. No access decision was made.")
    print(f"Output written to {args.out.resolve()}")
    return 1 if args.fail_on_high and high_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
