# 🔐 Azure Identity & Sign-In Security Analysis  
### Failed Logins • MFA Abuse • Impossible Travel • Privileged Activity

![Azure](https://img.shields.io/badge/Azure-Cloud%20Security-0078D4?logo=microsoftazure)
![Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-Detection%20Engineering-5C2D91?logo=microsoft)
![Entra ID](https://img.shields.io/badge/Entra%20ID-Identity%20Protection-1A73E8?logo=microsoft)
![SOC](https://img.shields.io/badge/SOC-Incident%20Response-FF6A00?logo=security)

---

## 📌 Project Overview

This project demonstrates **identity-focused threat detection and incident response** using **Microsoft Entra ID (Azure AD) Sign-In Logs**, **Audit Logs**, and **Azure Activity Logs** within **Microsoft Sentinel**.

The objective is to detect, investigate, and validate:
- Suspicious authentication activity
- MFA abuse and brute-force attempts
- Impossible travel scenarios
- Privilege and role assignment changes
- Administrative actions affecting Azure resources

This repository is designed as a **SOC / Threat Hunting portfolio project**, following real-world investigation workflows.

---

## 🎯 Detection Use Cases Covered

- Excessive failed sign-in attempts  
- MFA denial and MFA fatigue indicators  
- Brute-force credential attacks  
- Impossible travel logins across countries  
- Role assignment modifications  
- Azure VM deletion activity validation  

---

## ✅ Successful Sign-In Analysis (Baseline Validation)

### Purpose
Establish a **known-good authentication baseline** to confirm:
- MFA enforcement is working
- Conditional Access policies are effective
- Legitimate user behavior is understood

### KQL Query — Successful Sign-Ins
```kql
SigninLogs
| where ResultType == 0
| where UserPrincipalName == "lognpacific.com"
| extend 
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    OS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    MFAUsed = iff(isempty(MfaDetail), "No MFA", "MFA Used")
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AppDisplayName,
    Country,
    City,
    OS,
    Browser,
    MFAUsed
| order by TimeGenerated desc
```
## ✅ Successful Sign-In Analysis — Observation & Conclusion

### 🔍 Observations
- Sign-in originated from a **known and trusted geographic location**
- Device and browser matched **previously observed, trusted endpoints**
- **Multi-Factor Authentication (MFA)** challenge was successfully completed

### 📸 Evidence
<img width="1568" alt="Successful Sign-In" src="https://github.com/user-attachments/assets/72fb62a7-09e3-403e-81d2-b40db16d0a9a" />

### 🧭 Conclusion
This authentication event is **legitimate** and establishes a **trusted baseline** for future anomaly detection and identity-based threat investigations.

---

## ❌ Failed Sign-In Investigation

### 🎯 Purpose
Identify incorrect credential usage that may indicate:
- User error
- Early-stage brute-force attempts
- Credential stuffing activity

### 🔍 KQL Query — Failed Authentication Attempts
```kql
SigninLogs
| where ResultType != 0
| where ResultDescription contains "Invalid username or password"
| where TimeGenerated > ago(30d)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    LocationDetails,
    AppDisplayName,
    ResultDescription,
    ResultType
```
📌 Incident Summary

- **ResultType:** 50126 *(Invalid credentials)*
- **Location:** Seattle, Washington *(Residential IPv6)*
- **Application:** Azure Portal

📸 Evidence
<img width="1000" alt="Failed Login" src="https://github.com/user-attachments/assets/e304d486-11f6-48a5-ac2e-a383d12c2659" />
🧭 Conclusion

This event represents a single failed authentication attempt with no follow-up activity.
No immediate indicators of malicious behavior were observed; however, continued monitoring is recommended to detect potential repetition or escalation.


## 🌍 Impossible Travel Detection

### 🎯 Purpose
- Identify users authenticating from **multiple countries within unrealistic timeframes**
- Detect potential **credential compromise**, VPN abuse, or session hijacking

### 🔍 KQL Query — Country Aggregation
```kql
SigninLogs
| where TimeGenerated > ago(30d)
| extend Loc = parse_json(LocationDetails)
| extend Country = tostring(Loc.countryOrRegion)
| summarize
    SignInCount = count(),
    Countries = make_set(Country)
    by UserPrincipalName
| order by SignInCount desc
```
📸 Evidence

<img width="1557" alt="Impossible Travel" src="https://github.com/user-attachments/assets/c9499bd5-ca43-4bda-adba-c68097143e73" />

### 🧭 Analyst Assessment & Response

- The user account was observed authenticating from **multiple geographic locations**, triggering an **impossible travel / brute-force detection**.
- This behavior may indicate **credential compromise or automated attack activity**.

### 🛠️ Remediation & Monitoring Actions
- **Account Reset:** The user account password was reset to immediately contain potential compromise.
- **Security Enforcement:** MFA remains enforced to prevent unauthorized access.
- **Device Monitoring:** The affected device will be closely monitored for any additional suspicious authentication or activity attempts.

### 📌 Status
- Immediate risk contained
- Ongoing monitoring in place















## 🚨 Brute-Force Detection & Response

### 📌 Incident Description
- Multiple failed authentication attempts triggered a **brute-force alert** against a user account.

### 🛠️ Response Actions
- **Password Reset:** Invalidated potentially compromised credentials
- **MFA Enforcement:** Applied multi-factor authentication to strengthen account security
- **RBAC Hardening:** Restricted permissions to **least privilege**

Validation — Audit Log Review

```kql
AuditLogs
| where OperationName in (
    "Change user password",
    "Reset user password"
)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| project
    TimeGenerated,
    OperationName,
    TargetUser,
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
    Result
| order by TimeGenerated desc
```
📸 Evidence

<img width="1518" alt="Password Reset" src="https://github.com/user-attachments/assets/6862b102-8e13-4fca-a75a-ec872fd07fcf" />


### 🔎 Account Remediation Verification & Ongoing Monitoring

- The user password has been **successfully reset** as part of the containment process.
- **Azure Audit Logs** were reviewed to confirm that the password change was properly recorded and completed.
- No unauthorized password changes were detected during the review.
- The account will remain under **continuous monitoring** to detect any further authentication attempts or suspicious activity.

### 📌 Status
- Containment action verified
- No additional malicious activity observed
- Monitoring remains active

