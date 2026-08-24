<#
.SYNOPSIS
Exports starter Entra ID data for offline access review analysis.

.DESCRIPTION
This script is intentionally simple and read-only. Run it only in a lab or tenant
where you have permission to export directory metadata. Review output before
sharing because tenant data may contain personal or sensitive information.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = ".\exports"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Module -ListAvailable Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement)) {
    throw "Install Microsoft Graph PowerShell modules before running this script."
}

New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

Connect-MgGraph -Scopes "User.Read.All","Group.Read.All","Directory.Read.All","RoleManagement.Read.Directory"

Get-MgUser -All -Property Id,UserPrincipalName,DisplayName,UserType,AccountEnabled,CreatedDateTime,SignInActivity,AssignedLicenses,Department,JobTitle |
    Select-Object `
        Id,
        UserPrincipalName,
        DisplayName,
        UserType,
        AccountEnabled,
        CreatedDateTime,
        @{Name="signInActivityLastSignInDateTime";Expression={$_.SignInActivity.LastSignInDateTime}},
        @{Name="managerUserPrincipalName";Expression={""}},
        @{Name="assignedLicenses";Expression={($_.AssignedLicenses.SkuId -join ";")}},
        Department,
        JobTitle |
    Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath "users.csv")

Get-MgGroup -All -Property Id,DisplayName,SecurityEnabled,MailEnabled |
    Select-Object `
        Id,
        DisplayName,
        @{Name="owners";Expression={""}},
        @{Name="sensitivityLabel";Expression={""}},
        SecurityEnabled,
        MailEnabled |
    Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath "groups.csv")

Write-Host "Starter exports written to $OutputPath. Populate owners, memberships, and role assignment CSVs as needed."
