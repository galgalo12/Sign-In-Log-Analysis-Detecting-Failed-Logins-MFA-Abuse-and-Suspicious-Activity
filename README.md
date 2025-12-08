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

    ### Successful sign-ins login KQ
   
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


    
