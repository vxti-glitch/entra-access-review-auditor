# Entra Access Review Findings

## Summary

- Users reviewed: 5
- Groups reviewed: 4
- Memberships reviewed: 4
- Role assignments reviewed: 2
- Findings: 7

## Findings

| Severity | Category | Principal | Detail | Recommendation |
| --- | --- | --- | --- | --- |
| medium | disabled-licensed-user | taylor.disabled@contoso.com | Disabled account still has assigned licenses. | Review license assignment and remove unused licenses if no exception exists. |
| high | stale-guest-user | rachel.guest_example.com#EXT#@contoso.onmicrosoft.com | Guest account has no sign-in within 30 days. | Ask the sponsor to approve continued access or remove the guest. |
| low | missing-manager | casey.managerless@contoso.com | Enabled member account has no manager value. | Update the manager attribute to support approvals and access reviews. |
| high | ownerless-group | Global Admin Break Glass | Group does not have an owner recorded in the export. | Assign a business owner before the next access review. |
| high | guest-in-sensitive-group | rachel.guest_example.com#EXT#@contoso.onmicrosoft.com | Guest has membership in sensitive group 'Finance SharePoint Members'. | Require owner approval or remove the guest from the group. |
| high | privileged-role-review | taylor.disabled@contoso.com | Principal has eligible assignment to 'Global Administrator'. The principal account is disabled. | Confirm the role assignment is still required and covered by an access review. |
| high | privileged-role-review | alex.johnson@contoso.com | Principal has active assignment to 'User Administrator'. | Confirm the role assignment is still required and covered by an access review. |

## Suggested Review Cadence

- Review privileged roles monthly.
- Review guest access monthly or quarterly depending on risk.
- Review ownerless and sensitive groups before major audits.
- Track accepted exceptions in a ticket or change record.
