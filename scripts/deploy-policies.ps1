# =============================================================================
# Entra ID Conditional Access Policy Deployment Script
# =============================================================================
# Deploys all 5 Conditional Access policies and the named location using
# the Microsoft Graph PowerShell SDK.
#
# Prerequisites:
#   Install-Module Microsoft.Graph -Scope CurrentUser
#
# Usage:
#   .\deploy-policies.ps1
#
# All policies deploy in Report-only mode — no enforcement until you
# manually switch state to "enabled" after validation.
# =============================================================================

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns

param(
    [switch]$WhatIf,
    [string]$TenantId = ""
)

# ---------------------------------------------------------------------------
# Connect to Microsoft Graph
# ---------------------------------------------------------------------------
Write-Host "`n[+] Connecting to Microsoft Graph..." -ForegroundColor Cyan

$scopes = @(
    "Policy.ReadWrite.ConditionalAccess",
    "Policy.Read.All",
    "Directory.Read.All"
)

if ($TenantId) {
    Connect-MgGraph -TenantId $TenantId -Scopes $scopes
} else {
    Connect-MgGraph -Scopes $scopes
}

Write-Host "[+] Connected`n" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 1 — Retrieve group object IDs
# ---------------------------------------------------------------------------
Write-Host "[*] Resolving security group IDs..." -ForegroundColor Yellow

$groupStandardEmployees = (Get-MgGroup -Filter "displayName eq 'CA-Standard-Employees'").Id
$groupITAdmins          = (Get-MgGroup -Filter "displayName eq 'CA-IT-Administrators'").Id
$groupVendors           = (Get-MgGroup -Filter "displayName eq 'CA-External-Vendors'").Id

Write-Host "    CA-Standard-Employees : $groupStandardEmployees"
Write-Host "    CA-IT-Administrators  : $groupITAdmins"
Write-Host "    CA-External-Vendors   : $groupVendors"

if (-not ($groupStandardEmployees -and $groupITAdmins -and $groupVendors)) {
    Write-Error "One or more groups not found. Create the groups before running this script."
    exit 1
}

# ---------------------------------------------------------------------------
# Step 2 — Create Named Location: Allowed-Countries-CA-US
# ---------------------------------------------------------------------------
Write-Host "`n[*] Creating named location: Allowed-Countries-CA-US..." -ForegroundColor Yellow

$namedLocationParams = @{
    "@odata.type"                      = "#microsoft.graph.countryNamedLocation"
    displayName                        = "Allowed-Countries-CA-US"
    countriesAndRegions                = @("CA", "US")
    includeUnknownCountriesAndRegions  = $false
}

if (-not $WhatIf) {
    $namedLocation = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $namedLocationParams
    Write-Host "    [+] Named location created: $($namedLocation.Id)" -ForegroundColor Green
} else {
    Write-Host "    [WHATIF] Would create named location Allowed-Countries-CA-US" -ForegroundColor DarkYellow
    $namedLocation = @{ Id = "WHATIF-NAMED-LOCATION-ID" }
}

# ---------------------------------------------------------------------------
# Step 3 — CA-001: Require MFA for All Users
# ---------------------------------------------------------------------------
Write-Host "`n[*] Creating CA-001 — Require MFA for All Users..." -ForegroundColor Yellow

$ca001 = @{
    displayName = "CA-001 — Require MFA for All Users"
    state       = "enabledForReportingButNotEnforced"
    conditions  = @{
        users        = @{ includeUsers = @("All") }
        applications = @{ includeApplications = @("All") }
    }
    grantControls = @{
        operator         = "OR"
        builtInControls  = @("mfa")
    }
}

if (-not $WhatIf) {
    $policy1 = New-MgIdentityConditionalAccessPolicy -BodyParameter $ca001
    Write-Host "    [+] CA-001 created: $($policy1.Id)" -ForegroundColor Green
} else {
    Write-Host "    [WHATIF] Would create CA-001" -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------------------
# Step 4 — CA-002: Block Risky Locations
# ---------------------------------------------------------------------------
Write-Host "`n[*] Creating CA-002 — Block Risky Locations..." -ForegroundColor Yellow

$ca002 = @{
    displayName = "CA-002 — Block Risky Locations"
    state       = "enabledForReportingButNotEnforced"
    conditions  = @{
        users        = @{ includeUsers = @("All") }
        applications = @{ includeApplications = @("All") }
        locations    = @{
            includeLocations = @("All")
            excludeLocations = @($namedLocation.Id)
        }
    }
    grantControls = @{
        operator        = "OR"
        builtInControls = @("block")
    }
}

if (-not $WhatIf) {
    $policy2 = New-MgIdentityConditionalAccessPolicy -BodyParameter $ca002
    Write-Host "    [+] CA-002 created: $($policy2.Id)" -ForegroundColor Green
} else {
    Write-Host "    [WHATIF] Would create CA-002" -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------------------
# Step 5 — CA-003: Require Compliant Device for Admin Portals
# ---------------------------------------------------------------------------
Write-Host "`n[*] Creating CA-003 — Require Compliant Device for Admin Portals..." -ForegroundColor Yellow

$ca003 = @{
    displayName = "CA-003 — Require Compliant Device for Admin Portals"
    state       = "enabledForReportingButNotEnforced"
    conditions  = @{
        users        = @{ includeUsers = @("All") }
        applications = @{ includeApplications = @("MicrosoftAdminPortals") }
    }
    grantControls = @{
        operator        = "OR"
        builtInControls = @("compliantDevice")
    }
}

if (-not $WhatIf) {
    $policy3 = New-MgIdentityConditionalAccessPolicy -BodyParameter $ca003
    Write-Host "    [+] CA-003 created: $($policy3.Id)" -ForegroundColor Green
} else {
    Write-Host "    [WHATIF] Would create CA-003" -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------------------
# Step 6 — CA-004: Strict MFA for Admin Accounts
# ---------------------------------------------------------------------------
Write-Host "`n[*] Creating CA-004 — Strict MFA for Admin Accounts..." -ForegroundColor Yellow

$ca004 = @{
    displayName = "CA-004 — Strict MFA for Admin Accounts"
    state       = "enabledForReportingButNotEnforced"
    conditions  = @{
        users           = @{ includeGroups = @($groupITAdmins) }
        applications    = @{ includeApplications = @("All") }
        signInRiskLevels = @("low", "medium", "high")
    }
    grantControls = @{
        operator        = "OR"
        builtInControls = @("mfa")
    }
}

if (-not $WhatIf) {
    $policy4 = New-MgIdentityConditionalAccessPolicy -BodyParameter $ca004
    Write-Host "    [+] CA-004 created: $($policy4.Id)" -ForegroundColor Green
} else {
    Write-Host "    [WHATIF] Would create CA-004" -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------------------
# Step 7 — CA-005: Restrict Vendor Access
# ---------------------------------------------------------------------------
Write-Host "`n[*] Creating CA-005 — Restrict Vendor Access..." -ForegroundColor Yellow

$ca005 = @{
    displayName = "CA-005 — Restrict Vendor Access"
    state       = "enabledForReportingButNotEnforced"
    conditions  = @{
        users        = @{ includeGroups = @($groupVendors) }
        applications = @{ includeApplications = @("Office365") }
    }
    grantControls = @{
        operator        = "OR"
        builtInControls = @("mfa")
    }
}

if (-not $WhatIf) {
    $policy5 = New-MgIdentityConditionalAccessPolicy -BodyParameter $ca005
    Write-Host "    [+] CA-005 created: $($policy5.Id)" -ForegroundColor Green
} else {
    Write-Host "    [WHATIF] Would create CA-005" -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host " Deployment Complete" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Named Location : Allowed-Countries-CA-US"
Write-Host " CA-001 : Require MFA for All Users"
Write-Host " CA-002 : Block Risky Locations"
Write-Host " CA-003 : Require Compliant Device for Admin Portals"
Write-Host " CA-004 : Strict MFA for Admin Accounts"
Write-Host " CA-005 : Restrict Vendor Access"
Write-Host ""
Write-Host " All policies deployed in Report-only mode." -ForegroundColor Yellow
Write-Host " Validate with the What If tool before enabling enforcement." -ForegroundColor Yellow
Write-Host "============================================`n" -ForegroundColor Cyan

Disconnect-MgGraph
