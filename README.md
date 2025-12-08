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
- Sign-ins from risky IPs, VPNs, or TOR  

The goal is to provide a complete **identity-focused detection workflow** that helps SOC teams quickly find, investigate, and respond to authentication threats.
