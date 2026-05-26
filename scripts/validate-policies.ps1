# =============================================================================
# Entra ID Conditional Access — What If Validation Script
# =============================================================================
# Runs What If simulations against all deployed policies to validate behaviour
# before switching from Report-only to Enforced mode.
#
# Replicates the manual What If tests documented in the lab report:
#   Test 1 — US login (8.8.8.8)      → MFA required, not blocked
#   Test 2 — Germany login (185.220.101.1) → MFA + blocked
# =============================================================================

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns

param(
    [Parameter(Mandatory)]
    [string]$TestUserId,       # Object ID of the test user account

    [Parameter(Mandatory)]
    [string]$TenantId
)

Connect-MgGraph -TenantId $TenantId -Scopes "Policy.Read.All", "Directory.Read.All"

Write-Host "`n[+] Running What If validation tests...`n" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Test 1 — US login from 8.8.8.8 (should: MFA required, NOT blocked)
# ---------------------------------------------------------------------------
Write-Host "TEST 1 — US Login (IP: 8.8.8.8)" -ForegroundColor Yellow

$test1 = @{
    conditionalAccessWhatIfSubject = @{
        "@odata.type" = "#microsoft.graph.userSubject"
        userId        = $TestUserId
    }
    conditionalAccessContext = @{
        "@odata.type"       = "#microsoft.graph.ipv4CidrRange"
        ipAddress           = "8.8.8.8"
        includeApplications = @("All")
    }
}

$result1 = Invoke-MgWhatIfIdentityConditionalAccessPolicy -BodyParameter $test1
$result1.Value | ForEach-Object {
    $status = if ($_.Result -eq "reportOnlySuccess") { "[PASS]" } else { "[INFO]" }
    Write-Host "  $status $($_.DisplayName) — $($_.Result)"
}

Write-Host "`n  Expected: CA-001 fires (MFA required). CA-002 does NOT fire (US is excluded).`n"

# ---------------------------------------------------------------------------
# Test 2 — Germany login from 185.220.101.1 (should: MFA + blocked)
# ---------------------------------------------------------------------------
Write-Host "TEST 2 — Germany Login (IP: 185.220.101.1)" -ForegroundColor Yellow

$test2 = @{
    conditionalAccessWhatIfSubject = @{
        "@odata.type" = "#microsoft.graph.userSubject"
        userId        = $TestUserId
    }
    conditionalAccessContext = @{
        "@odata.type"       = "#microsoft.graph.ipv4CidrRange"
        ipAddress           = "185.220.101.1"
        includeApplications = @("All")
    }
}

$result2 = Invoke-MgWhatIfIdentityConditionalAccessPolicy -BodyParameter $test2
$result2.Value | ForEach-Object {
    $status = if ($_.Result -match "block") { "[BLOCK]" } else { "[INFO]" }
    Write-Host "  $status $($_.DisplayName) — $($_.Result)"
}

Write-Host "`n  Expected: CA-001 fires (MFA required). CA-002 fires (Block — Germany not in exclusion list).`n"

Disconnect-MgGraph
Write-Host "[+] Validation complete. Review results above before enabling enforcement.`n" -ForegroundColor Green
