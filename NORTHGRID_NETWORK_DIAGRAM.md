# NorthGrid Cloud Pivot — Azure-to-AWS-to-Site2 Attack Path

Identity/resource pivot path for the NorthGrid Cloud Pivot Assessment Guide scenario,
derived from `sentinel_iocs.py`. A compromised third-party contractor account is used
to ride trusted cloud access from Azure into AWS, ultimately reaching internal
engineering hosts. Renders automatically on GitHub.

```mermaid
graph TD
    ATT["External Attacker<br/>185.214.132.47 / .88<br/>45.9.148.112 / 91.219.236.47"]
    TEDDY["teddy.potts@northgrid.com<br/>compromised contractor account"]
    AAD["Entra ID / Azure AD<br/>Graph + directory enumeration"]
    SP["NorthGrid-CustomerAccess-SP<br/>service principal (abused)"]
    KV["Azure Key Vault<br/>AWS federation credentials"]
    ROLE["AWS IAM Role<br/>NorthGridEngineeringAccess<br/>arn:aws:iam::482917364820:role/..."]
    S3["S3 bucket<br/>site2-engineering-docs"]
    DECOY1["old_notes.txt<br/>(decoy)"]
    DECOY2["site2-eng2-maintenance.txt<br/>(decoy)"]
    DECOY3["deprecated_jumpbox_list.xlsx<br/>(decoy)"]
    TARGETFILE["eng4_jumpbox_access_notes.txt<br/>mission objective"]
    SVC["svc-northgrid-access@site2.com<br/>customer-side account reached"]
    DEV5["site2-dev5<br/>internal engineering host"]
    ENG4["site2-eng4<br/>OT jumpbox — final target"]

    ATT -->|T1078.004 credential compromise| TEDDY
    TEDDY -->|sign-in from attacker IPs| AAD
    AAD -->|T1087.004 discovery| SP
    SP -->|T1528 token abuse| KV
    KV -->|T1552.005 federation creds retrieved| ROLE
    TEDDY -.->|pivot to customer-side identity| SVC
    ROLE -->|T1550.001 AssumeRole| S3
    S3 --> DECOY1
    S3 --> DECOY2
    S3 --> DECOY3
    S3 -->|T1530 GetObject| TARGETFILE
    TARGETFILE -->|access details used| SVC
    SVC -->|T1021.001 RDP| DEV5
    DEV5 -->|lateral movement| ENG4

    classDef compromised fill:#f85149,stroke:#8b1a1a,color:#fff
    classDef pivot fill:#d29922,stroke:#8a5d00,color:#fff
    classDef decoy fill:#30363d,stroke:#484f58,color:#8b949e
    classDef target fill:#a371f7,stroke:#6e40c9,color:#fff
    class TEDDY,SP,ROLE,SVC compromised
    class AAD,KV,S3,DEV5 pivot
    class DECOY1,DECOY2,DECOY3 decoy
    class TARGETFILE,ENG4 target
```

**Legend:** red = compromised identity/principal, amber = pivoted-through Azure/AWS
resource, gray = decoy file (dead end), purple = true objective (target file and
final host).

## Identity & resource map

| Stage | Entity | Role in the attack |
|---|---|---|
| Initial access | teddy.potts@northgrid.com | Compromised NorthGrid contractor account |
| Azure enumeration | Entra ID / Graph | Directory, service principal, role assignment discovery |
| Credential access | NorthGrid-CustomerAccess-SP | Service principal abused to reach Key Vault |
| Credential access | Azure Key Vault | Source of AWS federation credentials |
| AWS pivot | arn:aws:iam::482917364820:role/NorthGridEngineeringAccess | Role assumed to cross into AWS |
| Collection | s3://site2-engineering-docs | Bucket containing decoys + the real target file |
| Collection (dead ends) | old_notes.txt, site2-eng2-maintenance.txt, deprecated_jumpbox_list.xlsx | Decoy files expected to be opened first |
| Collection (objective) | eng4_jumpbox_access_notes.txt | Real target — contains site2-eng4 access details |
| Pivot identity | svc-northgrid-access@site2.com | Customer-side account reached via the Azure pivot |
| Internal lateral movement | site2-dev5, site2-eng4 | Internal engineering hosts reached via RDP using the discovered access details |

Attacker IPs (185.214.132.47, 185.214.132.88, 45.9.148.112, 91.219.236.47) aren't drawn
as separate nodes per hop — they're the consistent `source.ip`/`CallerIpAddress` across
Phases 1-3 in `sentinel_iocs.py`, useful as a single pivot value across SigninLogs,
AzureActivity, and AWSCloudTrail. This diagram is derived from the assessment guide's
described attack path, not yet validated against live telemetry — see `sentinel_iocs.py`
notes for the real KQL to confirm each hop.
