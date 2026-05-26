# Entra ID Conditional Access Lab

**Enterprise Identity Security Framework — Microsoft Entra ID Premium P2**  
Oluwaseyi Michael Falode | Cybersecurity & Cloud Security Engineer | Toronto, ON | May 2026

![Microsoft Azure](https://img.shields.io/badge/Microsoft_Azure-0089D6?style=flat&logo=microsoft-azure&logoColor=white)
![Microsoft Entra ID](https://img.shields.io/badge/Microsoft_Entra_ID-0078D4?style=flat&logo=microsoft&logoColor=white)
![Zero Trust](https://img.shields.io/badge/Zero_Trust_Architecture-FF6B35?style=flat&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=flat&logo=powershell&logoColor=white)
![IAM](https://img.shields.io/badge/Identity_%26_Access_Management-5C2D91?style=flat&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-E63F2B?style=flat&logoColor=white)

---

A complete Conditional Access policy framework designed, deployed, and validated from scratch using Microsoft Entra ID Premium P2 — no pre-built templates, no wizards, no shortcuts. Five policies modelling the exact security controls a regulated financial institution like Scotiabank enforces across its entire user population: standard employees, IT administrators, and external vendors.

Every policy was built with real Microsoft Graph API-compatible JSON, deployed in Report-only mode following enterprise change management best practices, and validated using the built-in What If analysis tool before any enforcement. PowerShell deployment and validation scripts included — this framework can be reproduced in any Entra tenant in minutes.

## Project at a Glance

| | |
|---|---|
| **Platform** | Microsoft Azure · Microsoft Entra ID Premium P2 |
| **Policies Built** | 5 Conditional Access policies |
| **Policy Mode** | Report-only (pre-enforcement — enterprise change management standard) |
| **User Personas** | Standard Employee · IT Administrator · External Vendor |
| **Security Groups** | CA-Standard-Employees · CA-IT-Administrators · CA-External-Vendors |
| **Security Focus** | Zero Trust · MFA enforcement · Geo-blocking · Privileged access · Least privilege |
| **Frameworks** | Zero Trust Architecture · MITRE ATT&CK · Principle of Least Privilege |
| **Automation** | Microsoft Graph PowerShell SDK · What If API validation |
| **Completed** | May 2026 |

## The Problem This Project Solves

Identity is the new perimeter. In a cloud-first enterprise there is no physical network boundary protecting internal systems — every login is a potential attack surface. Microsoft research shows that over 99% of account compromise attacks are blocked by MFA alone. Yet most breaches still succeed because access controls are absent, misconfigured, or applied inconsistently across different user risk profiles.

A financial institution like Scotiabank faces three distinct threats simultaneously:

- **Threat 1 — Account takeover at scale:** Standard employees log into dozens of cloud applications every day. Without MFA enforced across all apps, a single phishing email is enough to hand an attacker full access. No MFA means no second barrier — credentials are the only thing standing between an attacker and the entire Microsoft 365 environment.

- **Threat 2 — Credential use from foreign regions:** Stolen credentials sold on dark web markets are immediately used by attackers operating from countries where the bank has no business presence. A bank operating in Canada and the Americas has no legitimate reason to allow logins from Germany, Russia, or China. Without geo-blocking, a valid credential is all an attacker needs regardless of where they are in the world.

- **Threat 3 — Privileged account compromise:** Admin accounts can modify security settings, create users, grant permissions, and access everything across the entire tenant. A compromised admin account is a full organizational breach. Standard MFA is not enough for accounts at this privilege level — they need dedicated policies, dedicated monitoring, and zero-tolerance controls at every risk level.

Conditional Access is Microsoft Entra's policy engine for enforcing adaptive access controls. Every policy in this framework addresses a specific threat, targets a specific user population, and operates with proportional controls — stricter for higher-risk identities and resources.

## Identity Structure

Three security groups segment users by role and risk level. Conditional Access policies target groups — not individual users — because this is the only approach that scales in an enterprise environment. Define the rule once, and it automatically applies to every current and future member of that group.

| Group | Member | Purpose |
|---|---|---|
| CA-Standard-Employees | Test Employee | Standard staff with everyday app access |
| CA-IT-Administrators | Test Admin | Privileged accounts with elevated system access |
| CA-External-Vendors | Test Vendor | External contractors with limited app access |

### Test Users Created

![Test Users](screenshots/figure-01-test-users.png)

*Figure 1 — All three test user accounts representing the three user personas in the tenant*

### Security Groups

![Security Groups](screenshots/figure-02-security-groups.png)

*Figure 2 — Three Assigned-membership security groups, each targeting a different risk profile*

![Standard Employees Group](screenshots/figure-03-standard-employees-group.png)

*Figure 3 — CA-Standard-Employees group with Test Employee as a direct member*

![IT Administrators Group](screenshots/figure-04-it-administrators-group.png)

*Figure 4 — CA-IT-Administrators group with Test Admin as a direct member*

---

## Policy Framework

### CA-001 — Require MFA for All Users

| | |
|---|---|
| **Scope** | All users → All cloud apps |
| **Access Control** | Require multifactor authentication |
| **Threat** | Account takeover via phishing or credential stuffing |
| **MITRE** | T1078 — Valid Accounts |

MFA is the single most effective identity control in existence. This is the baseline — every user, every app, every login, no exceptions. CA-001 ensures that even if an attacker obtains valid credentials, they cannot authenticate without the second factor.

```json
{
  "displayName": "CA-001 — Require MFA for All Users",
  "state": "enabledForReportingButNotEnforced",
  "conditions": {
    "users": { "includeUsers": ["All"] },
    "applications": { "includeApplications": ["All"] }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["mfa"]
  }
}
```

---

### CA-002 — Block Risky Locations

| | |
|---|---|
| **Scope** | All users → All cloud apps |
| **Exclusion** | Allowed-Countries-CA-US (Canada + United States) |
| **Access Control** | Block access |
| **Threat** | Credential use from foreign attackers post dark-web purchase |
| **MITRE** | T1078 — Valid Accounts (foreign origin) |

Login attempts from outside the approved geographic region are blocked before authentication begins. The named location `Allowed-Countries-CA-US` excludes Canada and the US from the block — every other country is blocked by default.

```json
{
  "displayName": "CA-002 — Block Risky Locations",
  "state": "enabledForReportingButNotEnforced",
  "conditions": {
    "users": { "includeUsers": ["All"] },
    "applications": { "includeApplications": ["All"] },
    "locations": {
      "includeLocations": ["All"],
      "excludeLocations": ["Allowed-Countries-CA-US"]
    }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["block"]
  }
}
```

---

### CA-003 — Require Compliant Device for Admin Portals

| | |
|---|---|
| **Scope** | All users → Microsoft Admin Portals |
| **Access Control** | Require device to be marked as compliant (Intune) |
| **Threat** | Admin portal access from unmanaged or compromised device |
| **MITRE** | T1078.004 — Cloud Accounts (Privilege Escalation) |

Admin portals are the highest-value targets in any organization. This policy ensures only Intune-enrolled, policy-compliant devices can access them. An attacker with stolen admin credentials and a personal laptop is blocked at the device layer.

```json
{
  "displayName": "CA-003 — Require Compliant Device for Admin Portals",
  "state": "enabledForReportingButNotEnforced",
  "conditions": {
    "users": { "includeUsers": ["All"] },
    "applications": { "includeApplications": ["MicrosoftAdminPortals"] }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["compliantDevice"]
  }
}
```

---

### CA-004 — Strict MFA for Admin Accounts

| | |
|---|---|
| **Scope** | CA-IT-Administrators → All cloud apps (sign-in risk: Low / Medium / High) |
| **Access Control** | Require multifactor authentication |
| **Threat** | Privileged account compromise |
| **MITRE** | T1078 / T1098 — Valid Accounts / Account Manipulation |

Admin accounts are challenged at **every** risk level with zero exceptions. CA-001 already covers all users — CA-004 creates a dedicated, separately auditable policy for admin identities so their sign-in activity can be monitored and tightened independently from standard users.

```json
{
  "displayName": "CA-004 — Strict MFA for Admin Accounts",
  "state": "enabledForReportingButNotEnforced",
  "conditions": {
    "users": { "includeGroups": ["CA-IT-Administrators"] },
    "applications": { "includeApplications": ["All"] },
    "signInRiskLevels": ["low", "medium", "high"]
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["mfa"]
  }
}
```

---

### CA-005 — Restrict Vendor Access

| | |
|---|---|
| **Scope** | CA-External-Vendors → Office 365 only |
| **Access Control** | Require multifactor authentication |
| **Threat** | Compromised vendor pivoting into sensitive internal systems |
| **MITRE** | T1078.004 — Cloud Accounts / Supply Chain |

Vendors are external parties. Scoping their access to Office 365 only means a compromised vendor credential cannot reach the Azure portal, Entra admin center, or any sensitive financial application. Principle of least privilege applied at the application layer.

```json
{
  "displayName": "CA-005 — Restrict Vendor Access",
  "state": "enabledForReportingButNotEnforced",
  "conditions": {
    "users": { "includeGroups": ["CA-External-Vendors"] },
    "applications": { "includeApplications": ["Office365"] }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["mfa"]
  }
}
```

---

### All 5 Policies — Report-only Mode

![All Policies](screenshots/figure-05-all-policies-report-only.png)

*Figure 5 — All 5 Conditional Access policies active in Report-only mode on the Entra portal dashboard*

---

## Named Location

The `Allowed-Countries-CA-US` named location defines the approved geographic boundary referenced in CA-002 as the geo-block exclusion. Country-based IP geolocation — any IP resolving outside Canada or the United States hits the block.

| Field | Value |
|---|---|
| Display Name | Allowed-Countries-CA-US |
| Type | Countries and Regions (IP-based geolocation) |
| Countries | Canada (CA) · United States (US) |
| Unknown countries | Excluded |
| Used in | CA-002 — Block Risky Locations |

![Named Location](screenshots/figure-06-named-location.png)

*Figure 6 — Allowed-Countries-CA-US named location showing Canada and United States as approved regions*

---

## What If Validation

All policies were validated using the Entra What If tool before enabling enforcement — the enterprise standard for pre-deployment CA policy testing. Two scenarios were tested to confirm correct policy behaviour.

### Test 1 — US Login (Expected: MFA only, not blocked)

**Scenario:** Test Employee logs in from IP `8.8.8.8` (United States)

| Policy | Result | Reason |
|---|---|---|
| CA-001 — Require MFA | Applied | All users policy — MFA required |
| CA-002 — Block Risky Locations | Not applied | US is in the Allowed-Countries exclusion |

**Outcome:** Login proceeds to MFA challenge. Location exclusion working correctly.

![What If US Login](screenshots/figure-07-whattif-us-login.png)

*Figure 7 — What If result: US login triggers CA-001 (MFA) only — CA-002 correctly excluded*

---

### Test 2 — Germany Login (Expected: MFA + blocked)

**Scenario:** Test Employee logs in from IP `185.220.101.1` (Germany)

| Policy | Result | Reason |
|---|---|---|
| CA-001 — Require MFA | Applied | All users policy |
| CA-002 — Block Risky Locations | Applied | Germany not in approved countries — access blocked |

**Outcome:** Login completely blocked. Both policies fire. In a live enforced environment this login never completes regardless of credential validity or MFA.

![What If Germany Login](screenshots/figure-08-whatif-germany-login.png)

*Figure 8 — What If result: Germany login triggers CA-001 + CA-002 — access denied*

---

## Policy Architecture

```
USER ATTEMPTS LOGIN
        |
        | Entra ID evaluates all Conditional Access policies simultaneously
        v
┌──────────────────────────────────────────────────────────────────┐
│  CA-002 — LOCATION CHECK                                         │
│  Login from Canada or United States?                             │
│    YES → Excluded from block — continue evaluation              │
│    NO  → BLOCKED immediately — authentication never completes   │
└────────────────────────────┬─────────────────────────────────────┘
                             │ location approved
                             v
┌──────────────────────────────────────────────────────────────────┐
│  CA-001 — MFA FOR ALL USERS                                      │
│  Every user, every app → MFA challenge required                  │
└────────────────────────────┬─────────────────────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
         (standard)      (IT admin)    (vendor)
              │              │              │
              v              v              v
         No additional   CA-004        CA-005
         policy          Strict MFA    Office 365
                         at ALL        only + MFA
                         risk levels
                             │
                        (admin portals)
                             │
                             v
                         CA-003
                         Intune-compliant
                         device required
```

---

## Repository Structure

```
entra-conditional-access-lab/
├── policies/
│   ├── CA-001-require-mfa-all-users.json
│   ├── CA-002-block-risky-locations.json
│   ├── CA-003-require-compliant-device-admin-portals.json
│   ├── CA-004-strict-mfa-admin-accounts.json
│   └── CA-005-restrict-vendor-access.json
├── named-locations/
│   └── allowed-countries-ca-us.json
├── scripts/
│   ├── deploy-policies.ps1       # Deploys all policies via Microsoft Graph PowerShell
│   └── validate-policies.ps1    # Runs What If API tests to validate before enforcement
├── screenshots/                 # 8 screenshots from the live Entra portal session
│   ├── figure-01-test-users.png
│   ├── ... (8 total)
│   └── figure-08-whatif-germany-login.png
├── docs/
│   └── Entra_CA_Lab_Report_Final.pdf
└── README.md
```

---

## How to Deploy This Framework

**Prerequisites:** Microsoft Entra ID Premium P2 tenant, Global Administrator or Security Administrator role

### Option A — PowerShell (Automated)

```powershell
# Install the Microsoft Graph PowerShell SDK
Install-Module Microsoft.Graph -Scope CurrentUser

# Deploy all 5 policies and the named location
.\scripts\deploy-policies.ps1 -TenantId "your-tenant-id"

# Validate with What If before enabling enforcement
.\scripts\validate-policies.ps1 -TestUserId "test-user-object-id" -TenantId "your-tenant-id"
```

### Option B — Microsoft Entra Portal (Manual)

```
1. Create security groups
   Entra admin center → Groups → New group
   Create: CA-Standard-Employees, CA-IT-Administrators, CA-External-Vendors
   Add test users as direct members of each group

2. Create named location
   Entra admin center → Security → Conditional Access → Named locations
   Create: Allowed-Countries-CA-US → Countries → Canada + United States

3. Create each policy
   Entra admin center → Security → Conditional Access → Policies → New policy
   Use JSON from policies/ folder as reference for each policy's configuration
   Set state to Report-only for all policies

4. Validate with What If
   Entra admin center → Security → Conditional Access → What If
   Test 1: User = Test Employee | IP = 8.8.8.8   → Expected: MFA only
   Test 2: User = Test Employee | IP = 185.220.101.1 → Expected: MFA + Block

5. Switch to Enforced (after validation)
   Confirm Report-only results match expected behaviour
   Change policy state from Report-only to Enabled
```

---

## Skills Demonstrated

**Identity & Access Management**
- Conditional Access policy design for a regulated financial institution environment
- Named location configuration using country-based IP geolocation
- Security group segmentation for scalable, role-based policy targeting
- Microsoft Intune device compliance integration with Conditional Access

**Zero Trust Architecture**
- Never trust, always verify — MFA enforced at every login regardless of network location
- Proportional controls — stricter access requirements for higher-sensitivity resources
- Least privilege at the application layer — vendor access scoped to minimum required apps
- Separate, auditable policy tracks for admin identities vs. standard users

**Enterprise Change Management**
- Report-only mode deployment before any enforcement — no disruption to live users
- What If tool validation to confirm policy behaviour before go-live
- Policy naming convention (CA-001 through CA-005) following enterprise standards

**Security Automation**
- Microsoft Graph API-compatible JSON policy definitions (deployable via Graph or PowerShell)
- PowerShell deployment script using Microsoft Graph PowerShell SDK
- PowerShell validation script automating What If API calls for repeatable testing

---

*Oluwaseyi Michael Falode · Cybersecurity & Cloud Security Engineer · Toronto, ON · May 2026*  
*linkedin.com/in/oluwaseyi-falode · github.com/seyifalode-cmd*
