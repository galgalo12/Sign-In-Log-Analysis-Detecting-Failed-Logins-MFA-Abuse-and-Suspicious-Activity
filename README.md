# 🔐 Sign-In Log Analysis: Failed Logins, MFA Abuse & Azure Activity

![Azure](https://img.shields.io/badge/Azure-Cloud%20Security-0078D4?logo=microsoftazure)
![Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-Detection%20Engineering-5C2D91?logo=microsoft)
![Threat Detection](https://img.shields.io/badge/Threat%20Detection-Identity%20Security-EA4335?logo=shield)
![Entra ID](https://img.shields.io/badge/Entra%20ID-Identity%20Logs-1A73E8?logo=microsoft)
![Security Analysis](https://img.shields.io/badge/SOC-Analysis%20%26%20Monitoring-FF6A00?logo=security)

This project analyzes **Azure AD (Entra ID) Sign-In Logs** and **Azure Activity Logs** to detect suspicious authentication behavior. It focuses on identifying:

- Failed login patterns  
- MFA abuse attempts  
- Unusual or high-risk sign-in locations  
- Legacy authentication usage  
- Suspicious administrative actions  

The project also includes the logic behind creating **custom Microsoft Sentinel detection rules**, such as:

- Excessive failed sign-ins  
- MFA denial & MFA fatigue attempts  
- Impossible travel logins  
- High-risk role assignments or policy changes   

The goal is to provide a complete **identity-focused detection workflow** that helps SOC teams quickly find, investigate, and respond to authentication threats.

    ###  Searched 1 Successful sign-ins login KQ
   
    SigninLogs
    | where ResultType == 0                                      // Successful sign-ins
    | where UserPrincipalName == "09ea149d52addb39c065c8c09ca9f216423c7c2ece26c347adeea2deed7162b1@lognpacific.com"
    | extend 
          Country = tostring(LocationDetails.countryOrRegion),
          City = tostring(LocationDetails.city),
          Latitude = tostring(LocationDetails.geoCoordinates.latitude),
          Longitude = tostring(LocationDetails.geoCoordinates.longitude),
          OS = tostring(DeviceDetail.operatingSystem),
          Browser = tostring(DeviceDetail.browser),
          MFAUsed = iff(isempty(MfaDetail), "No MFA", "MFA Used")
    | project 
          TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,Country, City, OS,Browser, MFAUsed, MfaDetail,
          ResultDescription,ResultType,LocationDetails,DeviceDetail
    | order by TimeGenerated des

    
    
  <img width="668" height="361" alt="successful login" src="https://github.com/user-attachments/assets/72fb62a7-09e3-403e-81d2-b40db16d0a9a" />



  ## 🔍 Incident Summary — Successful Sign-In Review (Azure Portal)
    
    **Date/Time:**  
    - **Local:** December 7, 2025 at 8:26 PM PST  
    - **UTC:** December 8, 2025 at 04:26:11 UTC  
    
    **User:** b1@lognpacific.com  
    **Result:** Successful authentication (ResultType = 0)
    
    **Sign-In Details:**  
    - **IP Address:** 4.4.43.202  
    - **Location:** Puyallup, Washington, USA  
    - **Device:** Windows 10 (EAWS-Laptop) – Azure AD Registered  
    - **Browser:** Microsoft Edge 142.0.0  
    - **Authentication:** MFA successfully completed  
    
    **Behavior Analysis:**  
    - Login occurred from a **previously known user location**.  
    - Device and browser match **trusted, previously observed endpoints**.  
    - No signs of suspicious activity such as:  
      - Unusual or impossible travel  
      - Unknown devices  
      - Strange IP addresses  
      - Failed or risky attempts prior to the login  
    
    **Conclusion:**  
    This sign-in event appears **legitimate**.  
    The user authenticated from a known location using a trusted Windows 10 device, and MFA was successfully completed.  
    No indicators of compromise or anomalies were detected in this authentication event.

 
 Searched 2 Investigate failed or suspicious sign-ins for a specific user/domain
 
        // Investigate failed or suspicious sign-ins for a specific user/domain
        SigninLogs
        // Filter for a specific user (replace with actual UPN)
        | where UserPrincipalName == ""
        | where ResultDescription contains "Invalid username or password or Invalid on-premise username or password"
        // Only show failed or error sign-in attempts (ResultType != 0)
        | where ResultType != 0
        // Look back 30 days from the current date/time
        | where TimeGenerated <= ago(30d)
        // Select useful fields for investigation
        | project 
            TimeGenerated,         // Timestamp of the sign-in attempt
            UserPrincipalName,     // User account involved in the login
            IPAddress,             // Source IP address of the sign-in
            LocationDetails,       // Geo-location (country, city, coordinates)
            AppDisplayName,        // Application the user attempted to access
            MfaDetail,             // MFA information (challenge, success, failure)
            ResultDescription,     // Reason the login failed (e.g., bad password)
            ResultType             // Numeric result code (0 = success, non-zero = failure)
 
    
## ❗ Incident Summary — Failed Sign-In Attempt (Azure Portal)

        **Date/Time (UTC):**  
        2025-11-05 00:21:13
        
        **User:** @lognpacific.com  
        **Application:** Azure Portal  
        **Result:** Failed authentication (ResultType **50126**)  
        **Failure Reason:** Invalid username or password (or invalid on-prem AD credentials)
        
        **Sign-In Source:**  
        - **IP Address:** 2601:601:700:130:85ea:3560:b33e:aef  
        - **Location:** Seattle, Washington, United States  
          - Latitude: 47.5662  
          - Longitude: -122.3336  
        
        **Analysis:**  
        This failed sign-in originated from a **Seattle residential IPv6 address**, which aligns with typical user activity. ResultType **50126** indicates incorrect credentials were entered or the identity couldn’t be validated in a hybrid environment.  
        A single failed attempt may be accidental, but it can also serve as an early indicator of credential misuse if repeated.
        
        **Conclusion:**  
        This appears to be an isolated failed login with no immediate signs of malicious activity. Continued monitoring is recommended—especially for repeated failures or unusual login patterns.


<img width="668" height="362" alt="Failed login for all user" src="https://github.com/user-attachments/assets/e304d486-11f6-48a5-ac2e-a383d12c2659" />



Detect Role Assignment Changes in Azure Activity Logs
    
    // 🔍 Search Azure Activity Logs for any role assignment changes
    AzureActivity
    // 🎯 Filter only events where someone creates or modifies a role assignment
    | where OperationNameValue contains "roleAssignments/write"
    // 📌 Select the most important fields for investigation
    | project 
        TimeGenerated,        // ⏱️ When the action happened
        Caller,               // 👤 Who performed the action (user/SPN)
        Claims,               // 🪪 Token identity details (tenant, appId, issuer, etc.)
        ActivityStatusValue,  // ✅ Whether the operation succeeded or failed
        ResourceId            // 📍 Resource impacted (subscription, RG, VM, etc.)

<img width="856" height="395" alt="Permission for Azure-acitiviy" src="https://github.com/user-attachments/assets/96e1859c-3f9c-4df0-9839-4a056a85c590" />

# 🛑 Incident Summary – Unauthorized-Looking VM Deletion  
### *(Validated as Authorized Activity)*

## 📌 Overview
On **December 9, 2025**, Azure Activity Logs recorded a `roleAssignments/write` operation followed by **virtual machine deletion activity**. At first glance, this appeared suspicious and raised concerns about potential unauthorized privilege escalation or malicious administrative action.

A full investigation was conducted to determine **who initiated the role change**, **which tenant the identity belonged to**, and whether the permissions used were **legitimate**.

---

## 🔍 Key Findings

### ✔️ 1. Role Assignment Event Origin
A successful `roleAssignments/write` event was observed:

- **Time (UTC):** 2025-12-09T00:51:43Z  
- **Identity Type:** Service Principal (Application)  
- **Caller Object ID:** `5deb2a08-7269-47d6-896b-8b396466`  
- **AppId:** `84ca03a6-49c1-42a2-b903-42980167f6`  

Token and claim validation confirmed the activity originated from a **legitimate Azure AD service principal**.

---

### ✔️ 2. Tenant Verification
The caller identity was confirmed to belong to the correct tenant:

- **Tenant ID:** `939e93f3-04f6-479d-82ff-345c24d`  
- **Issuer (iss):** `https://sts.windows.net/<tenantID>/`  
- **Audience (aud):** `https://management.azure.com`  

This proves the activity came from **within the same Microsoft Entra tenant**, not from an external or cross-tenant source.

---

### ✔️ 3. Permission Validation
The service principal is a member of an **authorized Azure AD group**:

- **Group ID:** `b1cfafda-2028-40b9-a-455b54514dec`

This group has elevated IAM permissions, including:

- Virtual machine deletion  
- Network resource deletion  
- Resource group–level administrative actions  

Because these permissions were already assigned, both the **role assignment action** and the **VM deletion** were expected behaviors and succeeded without error.

---

### ✔️ 4. No Indicators of Malicious Activity
During the review:

- All token claims were valid and signed by Microsoft  
- The identity and tenant alignment were correct  
- No suspicious IP addresses or external actors were involved  
- No privilege escalation outside expected permissions occurred  

The activity aligns with **normal, authorized administrative operations** performed by a trusted service principal.

---

## 🧭 Conclusion
The investigation confirms that the VM deletion was performed by a **legitimately authorized identity** within the correct tenant. The service principal had the required role assignments and IAM permissions to perform this action.

**This event is categorized as Expected Administrative Activity, not a security incident.**











