# Entra Access-Review Candidate Helper

[![Python tests](https://github.com/vxti-glitch/entra-access-review-auditor/actions/workflows/python-tests.yml/badge.svg)](https://github.com/vxti-glitch/entra-access-review-auditor/actions/workflows/python-tests.yml)
![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Mode](https://img.shields.io/badge/Mode-offline%20read--only-2E8B57)

An offline helper that parses Microsoft Entra ID CSV exports and prepares cautious access-review candidates. It does not audit a tenant, assign risk, prove inactivity, or make access decisions. Every candidate requires review by an authorized owner or IAM reviewer.

The checked-in samples and reports use synthetic Contoso data. No live tenant integration was performed for the repository examples.

## What it does

- Keeps sign-in evidence explicit as `known_recent`, `known_stale`, or `unknown`; blank and unparseable values remain unknown.
- Separates unavailable group-owner export data from a confirmed empty owner list.
- Uses documented configuration for stale thresholds, sensitive-group heuristics, privileged-role heuristics, and explicit service-account exclusions.
- Records whether a classification is direct or heuristic and includes the exact configured rule that triggered it.
- Produces Markdown and JSON candidate reports for human review.

Keyword or pattern matches are triage heuristics, not security conclusions. Names, roles, and group labels can be custom, localized, or misleading.

## Quick start

```powershell
python .\src\entra_auditor.py `
  --users .\samples\users.csv `
  --groups .\samples\groups.csv `
  --memberships .\samples\group_memberships.csv `
  --roles .\samples\role_assignments.csv `
  --config .\config\review-rules.json `
  --out .\reports
```

Generated files:

- `reports/access-review-candidates.json`
- `reports/access-review-candidates.md`

See the checked-in [synthetic Markdown example](docs/examples/access-review-candidates.md), [synthetic JSON example](docs/examples/access-review-candidates.json), and [review rules](config/review-rules.json).

`--fail-on-high` can make an automation job exit with code 1 when a high-priority candidate exists. That exit code is a workflow signal only; it does not establish risk or authorize a change.

## Input boundary

`users.csv` requires identity, account-enabled, creation, sign-in, manager, and license fields documented by the sample header. Missing or invalid last-sign-in data produces an unknown-data candidate, never a stale conclusion.

`groups.csv` requires `id`, `displayName`, `owners`, and `sensitivityLabel`. Add `ownersDataStatus` with either:

- `available`: the export included owner data; a blank `owners` value can become an ownerless candidate.
- `unavailable`: owner coverage was not obtained; the helper reports that ownership is unknown.

If `ownersDataStatus` is absent or invalid, the helper fails closed to `unavailable`.

`group_memberships.csv` and optional `role_assignments.csv` use the included sample headers. Records that cannot be joined or lack core role fields are labeled ambiguous for human review.

## Configuration

[`config/review-rules.json`](config/review-rules.json) contains:

- Member and guest stale-day thresholds.
- Sensitive-group identifiers and regular-expression heuristics.
- Privileged-role identifiers and optional regular-expression heuristics.
- Explicit service-account IDs/UPNs and optional configured patterns.

The default service-account list contains only synthetic sample identifiers. A substring such as `svc` is not enough to exclude an account. Unknown identities default to human review.

## Verification scope

Automated tests cover unknown sign-ins, unavailable owner data, false-positive names, explicit service accounts, configurable thresholds, custom/non-English role names, ambiguous records, and heuristic-rule attribution. The example reports are regenerated from synthetic CSVs.

Not demonstrated: live Graph export permissions, tenant data completeness, access-review decisions, remediation, production controls, or compliance outcomes. Do not publish real tenant exports; manually review candidate reports for identifiers and sensitive data before sharing.
