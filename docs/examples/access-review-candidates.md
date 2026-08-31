# Entra Access-Review Candidates

> Candidate helper output, not an audit conclusion. Final decisions belong to an authorized owner or IAM reviewer.

## Summary

- Users parsed: 5
- Groups parsed: 4
- Memberships parsed: 4
- Role assignments parsed: 2
- Candidates: 6

## Candidates

| Priority | Category | Principal | Sign-in state | Classification | Triggered rule | Detail | Next step |
| --- | --- | --- | --- | --- | --- | --- | --- |
| medium | disabled-licensed-user | taylor.disabled@contoso.com | known_stale | direct | `accountEnabled=false AND assignedLicenses not empty` | The export shows a disabled account with assigned licenses. | Ask an authorized license owner to confirm whether an exception or removal is appropriate. |
| high | stale-guest-candidate | rachel.guest_example.com#EXT#@contoso.onmicrosoft.com | known_stale | direct | `lastSignInDateTime < today-30d` | The recorded last sign-in is older than the configured 30-day threshold. | An authorized owner or IAM reviewer must confirm context and decide whether access changes are appropriate. |
| low | missing-manager-candidate | casey.managerless@contoso.com | known_recent | direct | `manager empty AND no explicit service-account rule` | The export has no manager value and the identity is not an explicitly configured service account. | Determine the account type and responsible owner; do not infer employment status from this field alone. |
| high | confirmed-ownerless-group-candidate | Global Admin Break Glass | unknown | heuristic | `sensitive_group.identifier:g-003` | Owner data was available and no owner was recorded. | An authorized group administrator must confirm ownership and remediation. |
| high | guest-sensitive-group-candidate | rachel.guest_example.com#EXT#@contoso.onmicrosoft.com | known_stale | heuristic | `sensitive_group.pattern:\b(finance|payroll|break[ -]?glass|privileged)\b` | A guest is listed in group 'Finance SharePoint Members', which matched a configured sensitive-group heuristic. | The authorized group owner or IAM reviewer must decide whether membership is appropriate. |
| high | privileged-role-review-candidate | taylor.disabled@contoso.com | known_stale | heuristic | `privileged_role.identifier:Global Administrator` | The role name 'Global Administrator' matched a configured privileged-role heuristic. The exported principal account is disabled. | An authorized role owner or IAM reviewer must confirm necessity and assignment state. |
