# AutoADEnum
Active Directory enumeration
AutoADEnum

Advanced Active Directory Enumeration, Misconfiguration Discovery, and Attack Path Analysis Framework for Red Team, Internal Pentest, and AD Security Assessments.

Overview

AutoADEnum is a PowerShell-based Active Directory assessment framework designed to automate high-value LDAP enumeration, privilege exposure analysis, delegation abuse discovery, ACL takeover detection, GPO abuse inspection, and attack-path identification inside enterprise AD environments.

The framework focuses on:

Offensive security assessments
Internal Active Directory pentests
Red Team operations
AD security reviews
Attack surface mapping
Misconfiguration discovery

Unlike lightweight enumeration scripts, AutoADEnum correlates collected objects and relationships to identify exploitable privilege paths and high-risk configurations.

Features
Active Directory Enumeration
Users
Groups
Computers
Domain Controllers
Organizational Units
Trusts
GPOs
SPNs
Nested memberships
Effective privileges
Kerberos Attack Surface Discovery
Kerberoastable accounts
AS-REP roastable accounts
Delegation exposure
Protocol transition
Resource-Based Constrained Delegation (RBCD)
Privilege & Exposure Analysis
Privileged users
Critical group memberships
Nested privilege inheritance
AdminCount discovery
Dangerous group identification
Stale accounts
Password policy weaknesses
ACL & Permission Abuse Detection
GenericAll
GenericWrite
WriteDACL
WriteOwner
Delegated object takeover paths
Dangerous ACE discovery
GPO Security Analysis
GPO link mapping
SYSVOL inspection
Script discovery
GPP cpassword detection
Startup/Logon script inventory
Trust Enumeration
Forest trusts
External trusts
Trust directions
Trust attributes
SID filtering visibility
Attack Path Correlation
Relationship mapping
Privilege escalation paths
Delegation chains
Dangerous ACL relationships
Lateral movement exposure
Key Capabilities
Pure PowerShell
LDAP-native enumeration
No external dependencies required
Structured findings engine
Risk classification system
Attack-path inference
Enterprise-scale support
CSV/JSON export support
Operationally useful reporting
Example Findings
Kerberoastable service accounts
ASREP roastable users
Unconstrained delegation exposure
Dangerous delegated ACLs
Privileged nested group chains
GPP password exposure
Stale privileged accounts
Weak password policy indicators
Legacy operating systems
Excessive privilege inheritance
Usage

<img width="1089" height="825" alt="image" src="https://github.com/user-attachments/assets/af495d22-e943-4273-beaf-64f676d1e0a7" />

--------------------------------------------------------------------------------------------------------------------------------------

<img width="1071" height="750" alt="image" src="https://github.com/user-attachments/assets/a4f132fd-b41a-416c-aef7-edcc9785198f" />



Output

<img width="945" height="311" alt="image" src="https://github.com/user-attachments/assets/18c373a5-af33-4680-a517-cde895537259" />


The framework generates structured output directories containing:

Findings
Attack paths
Relationship mappings
CSV exports
JSON exports
Risk summaries
Console reporting

Example:

ADEnum_Output_20260518_130000/
Risk Levels
Risk	Description
Critical	Direct privilege escalation or credential compromise paths
Medium	Security weaknesses that may enable lateral movement
Low	Hygiene issues and security posture weaknesses
Info	Informational findings
Example Attack Vectors Detected
Kerberoasting
AS-REP Roasting
Unconstrained Delegation
Constrained Delegation Abuse
RBCD
Dangerous ACL Delegation
GPP Password Exposure
Privileged Nested Memberships
Stale Privileged Accounts
Legacy Systems Exposure
OPSEC Notes

This framework performs extensive LDAP enumeration and may generate:

LDAP query volume
Directory access events
SYSVOL access
ACL inspection activity

Use responsibly during authorized engagements.


Author

Hesham
