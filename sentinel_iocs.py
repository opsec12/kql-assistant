"""
Engagement-specific detection knowledge base for KQL Assistant — Sentinel/Kusto flavor.

Built from the "NorthGrid Cloud Pivot Assessment Guide": a compromised third-party
contractor identity is used to pivot from Azure (Entra ID / Key Vault / service
principals) into AWS (AssumeRole -> S3) to locate access information for the
site2-eng4 engineering jumpbox, then pivot internally via RDP.

This is real Kusto Query Language (KQL) as used in Microsoft Sentinel / Log
Analytics — pipe syntax against actual table schemas (SigninLogs, AuditLogs,
AWSCloudTrail, etc.) — NOT Elasticsearch's Kibana Query Language. Keep this file
and iocs.py (the Elastic flavor) separate; the syntax and table/field model are
unrelated.

Defensive content only, built from a training exercise ops doc.
"""

KNOWN_INFRASTRUCTURE = {
    "compromised_accounts": [
        "teddy.potts@northgrid.com",      # initial contractor compromise
        "svc-northgrid-access@site2.com",  # downstream service account reached via pivot
    ],
    "attacker_ips": [
        "185.214.132.47",
        "185.214.132.88",
        "45.9.148.112",
        "91.219.236.47",
    ],
    "target_service_principal": "NorthGrid-CustomerAccess-SP",
    "target_aws_role_arn": "arn:aws:iam::482917364820:role/NorthGridEngineeringAccess",
    "decoy_files": [
        "/site2-dev5/old_notes.txt",
        "/archive/site2-eng2-maintenance.txt",
        "/engineering/deprecated_jumpbox_list.xlsx",
    ],
    "target_file": "/site2-eng4/maintenance/eng4_jumpbox_access_notes.txt",
    "internal_systems": ["site2-dev5", "site2-eng4"],
    "relevant_tables": [
        "SigninLogs", "AADUserRiskEvents", "AADRiskyUsers",
        "MicrosoftGraphActivityLogs", "AADGraphActivityLogs", "AuditLogs", "AzureActivity",
        "AADServicePrincipalSignInLogs", "AADManagedIdentitySignInLogs",
        "AWSCloudTrail", "AWSGuardDuty", "AWSS3ServerAccess", "AWSVPCFlow",
        "SecurityEvent", "DeviceProcessEvents", "DeviceNetworkEvents",
    ],
}

DETECTIONS = [
    {
        "id": "full-attack-path-reconstruction",
        "name": "Full attack path reconstruction (all 6 phases, one query)",
        "tactic": "Multiple (Initial Access -> Discovery -> Credential Access -> Lateral Movement -> Collection)",
        "technique_id": "N/A (composite hunt)",
        "technique_name": "Cross-phase timeline reconstruction",
        "indicators": ["all known IOCs, unioned and phase-tagged"],
        "kql": (
            'let compromisedUser = "teddy.potts@northgrid.com";\n'
            'let compromisedIPs = dynamic(["185.214.132.47","185.214.132.88","45.9.148.112","91.219.236.47"]);\n'
            'let targetSP = "NorthGrid-CustomerAccess-SP";\n'
            'let awsRole = "NorthGridEngineeringAccess";\n'
            'let targetFile = "eng4_jumpbox_access_notes";\n'
            'union isfuzzy=true\n'
            '    (SigninLogs | where UserPrincipalName == compromisedUser or IPAddress in (compromisedIPs)\n'
            '        | extend Phase="1-ContractorCompromise", Detail=strcat(ResultType, " from ", IPAddress)),\n'
            '    (AADUserRiskEvents | where UserPrincipalName == compromisedUser\n'
            '        | extend Phase="1-ContractorCompromise", Detail=RiskEventType),\n'
            '    (AuditLogs | where InitiatedBy has compromisedUser or TargetResources has targetSP\n'
            '        | extend Phase="2-AzureEnumeration", Detail=ActivityDisplayName),\n'
            '    (AADServicePrincipalSignInLogs | where ServicePrincipalName == targetSP\n'
            '        | extend Phase="3-CredentialDiscovery", Detail=ResultType),\n'
            '    (AzureActivity | where OperationNameValue has "Microsoft.KeyVault"\n'
            '        | extend Phase="3-CredentialDiscovery", Detail=OperationNameValue),\n'
            '    (AWSCloudTrail | where UserIdentityArn has awsRole\n'
            '        | extend Phase="4-AWSPivot", Detail=EventName),\n'
            '    (AWSS3ServerAccess | where RequestURI has targetFile\n'
            '        | extend Phase="5-DocDiscovery", Detail=RequestURI),\n'
            '    (SecurityEvent | where Computer has_any ("site2-dev5","site2-eng4") and EventID in (4624,4625)\n'
            '        | extend Phase="6-InternalAccess", Detail=strcat("EventID ", EventID))\n'
            '| project TimeGenerated, Phase, Type, Detail\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": (
            "Answers the instructor validation checklist end-to-end in one query — run this "
            "first to get the shape of the whole intrusion, then drill into individual phases "
            "below for detail/tuning."
        ),
    },
    {
        "id": "compromised-infrastructure-timeline",
        "name": "All activity from known attacker IPs, across Azure/AWS/endpoint",
        "tactic": "Reconnaissance / Initial Access",
        "technique_id": "N/A (IOC pivot)",
        "technique_name": "Indicator-based hunting",
        "indicators": ["185.214.132.47", "185.214.132.88", "45.9.148.112", "91.219.236.47"],
        "kql": (
            'union isfuzzy=true\n'
            '    (SigninLogs | where IPAddress in ("185.214.132.47","185.214.132.88","45.9.148.112","91.219.236.47")),\n'
            '    (AzureActivity | where CallerIpAddress in ("185.214.132.47","185.214.132.88","45.9.148.112","91.219.236.47")),\n'
            '    (AWSCloudTrail | where SourceIpAddress in ("185.214.132.47","185.214.132.88","45.9.148.112","91.219.236.47")),\n'
            '    (DeviceNetworkEvents | where RemoteIP in ("185.214.132.47","185.214.132.88","45.9.148.112","91.219.236.47"))\n'
            '| project TimeGenerated, Type,\n'
            '    IPAddress = coalesce(column_ifexists("IPAddress",""), column_ifexists("CallerIpAddress",""), column_ifexists("SourceIpAddress",""), column_ifexists("RemoteIP","")),\n'
            '    Identity = coalesce(column_ifexists("UserPrincipalName",""), column_ifexists("Caller",""), column_ifexists("UserIdentityArn",""), column_ifexists("DeviceName",""))\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": (
            "One of these IPs (185.214.132.47) overlaps with the casepilot360.com C2 redirector "
            "from the earlier ops plan — worth checking whether this is deliberate infra reuse "
            "across exercises before treating it as a coincidence."
        ),
    },
    {
        "id": "contractor-failed-then-success-signin",
        "name": "Failed sign-ins immediately preceding successful access (password spray / brute force pattern)",
        "tactic": "Credential Access / Initial Access",
        "technique_id": "T1110 / T1078.004",
        "technique_name": "Brute Force / Valid Accounts: Cloud Accounts",
        "indicators": ["teddy.potts@northgrid.com"],
        "kql": (
            'SigninLogs\n'
            '| where UserPrincipalName == "teddy.potts@northgrid.com"\n'
            '| project TimeGenerated, ResultType, ResultDescription, Location, IPAddress,\n'
            '    RiskLevelDuringSignIn, RiskState, AppDisplayName\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Look for a cluster of ResultType != 0 (failures) immediately followed by ResultType == 0 (success) from a new location/IP.",
    },
    {
        "id": "contractor-risk-detections",
        "name": "Identity risk detections tied to the contractor account",
        "tactic": "Initial Access",
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "indicators": ["teddy.potts@northgrid.com", "svc-northgrid-access@site2.com"],
        "kql": (
            'union isfuzzy=true\n'
            '    (AADUserRiskEvents | where UserPrincipalName in ("teddy.potts@northgrid.com","svc-northgrid-access@site2.com")),\n'
            '    (AADRiskyUsers | where UserPrincipalName in ("teddy.potts@northgrid.com","svc-northgrid-access@site2.com"))\n'
            '| project TimeGenerated, Type, UserPrincipalName,\n'
            '    Detail = coalesce(column_ifexists("RiskEventType",""), column_ifexists("RiskLevel",""))\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Multiple geographic locations + elevated risk state on a contractor account is the earliest reliable signal in this whole chain.",
    },
    {
        "id": "azure-graph-enumeration",
        "name": "Microsoft Graph / Entra ID enumeration",
        "tactic": "Discovery",
        "technique_id": "T1087.004 / T1526",
        "technique_name": "Account Discovery: Cloud Account / Cloud Service Discovery",
        "indicators": ["teddy.potts", "NorthGrid", "role assignment review", "service principal discovery"],
        "kql": (
            'union isfuzzy=true\n'
            '    (MicrosoftGraphActivityLogs | where UserId has "teddy.potts" or AppId has "NorthGrid"),\n'
            '    (AADGraphActivityLogs | where Identity has "teddy.potts" or Identity has "NorthGrid"),\n'
            '    (AuditLogs | where ActivityDisplayName has_any\n'
            '        ("Add service principal","List service principals","List role assignments")),\n'
            '    (AzureActivity | where OperationNameValue has_any ("roleAssignments","servicePrincipals"))\n'
            '| project TimeGenerated, Type,\n'
            '    OperationName = coalesce(column_ifexists("OperationName",""), column_ifexists("ActivityDisplayName",""), column_ifexists("OperationNameValue","")),\n'
            '    Caller = coalesce(column_ifexists("Caller",""), column_ifexists("InitiatedBy",""), column_ifexists("UserId",""))\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "This step is designed to blend with normal admin/automation activity — expect noise; correlate timing against the Phase 1 compromise window to cut false positives.",
    },
    {
        "id": "key-vault-access-attempts",
        "name": "Key Vault read attempts (failed and successful)",
        "tactic": "Credential Access",
        "technique_id": "T1555.006",
        "technique_name": "Credentials from Password Stores: Cloud Secrets Management Stores",
        "indicators": ["Microsoft.KeyVault"],
        "kql": (
            'AzureActivity\n'
            '| where OperationNameValue has "Microsoft.KeyVault"\n'
            '| project TimeGenerated, OperationNameValue, ActivityStatusValue, Caller, CallerIpAddress, Resource\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Watch for failed reads followed shortly by a successful read — that transition is the actual credential-discovery moment referenced in Phase 3.",
    },
    {
        "id": "service-principal-abuse",
        "name": "NorthGrid-CustomerAccess-SP usage / abuse",
        "tactic": "Privilege Escalation / Lateral Movement",
        "technique_id": "T1550.001",
        "technique_name": "Use Alternate Authentication Material: Application Access Token",
        "indicators": ["NorthGrid-CustomerAccess-SP"],
        "kql": (
            'union isfuzzy=true\n'
            '    (AADServicePrincipalSignInLogs | where ServicePrincipalName == "NorthGrid-CustomerAccess-SP"\n'
            '        or AppDisplayName == "NorthGrid-CustomerAccess-SP"),\n'
            '    (AADManagedIdentitySignInLogs | where ServicePrincipalName has "NorthGrid"),\n'
            '    (AuditLogs | where TargetResources has "NorthGrid-CustomerAccess-SP")\n'
            '| project TimeGenerated, Type,\n'
            '    ServicePrincipalName = column_ifexists("ServicePrincipalName",""),\n'
            '    ResultType = column_ifexists("ResultType",""),\n'
            '    IPAddress = column_ifexists("IPAddress","")\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "This service principal is the bridge between the compromised Entra identity and the downstream AWS federation trust.",
    },
    {
        "id": "aws-assumerole-pivot",
        "name": "AssumeRole into NorthGridEngineeringAccess (Azure-to-AWS pivot)",
        "tactic": "Lateral Movement (cross-cloud)",
        "technique_id": "T1199 / T1550.001",
        "technique_name": "Trusted Relationship / Use Alternate Authentication Material",
        "indicators": ["arn:aws:iam::482917364820:role/NorthGridEngineeringAccess", "AssumeRole"],
        "kql": (
            'AWSCloudTrail\n'
            '| where EventName == "AssumeRole"\n'
            '| where RequestParameters has "NorthGridEngineeringAccess"\n'
            '    or ResponseElements has "NorthGridEngineeringAccess"\n'
            '| project TimeGenerated, EventName, SourceIpAddress, UserIdentityArn, ErrorCode, ResponseElements\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "A failed AssumeRole followed by a successful one from the same source IP is the highest-fidelity single event in the entire kill chain — this is the moment trust boundaries actually get crossed.",
    },
    {
        "id": "aws-s3-enumeration",
        "name": "S3 enumeration / object retrieval via the assumed role",
        "tactic": "Collection / Discovery",
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "indicators": ["GetObject", "ListObjects", "ListBucket", "NorthGridEngineeringAccess"],
        "kql": (
            'AWSCloudTrail\n'
            '| where EventName in ("GetObject","ListObjects","ListObjectsV2","ListBucket")\n'
            '| where UserIdentityArn has "NorthGridEngineeringAccess"\n'
            '| project TimeGenerated, EventName, SourceIpAddress, UserIdentityArn, RequestParameters, ErrorCode\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Pair with the S3ServerAccess query below to see exactly which objects/paths were touched, not just the API calls.",
    },
    {
        "id": "engineering-doc-access-with-decoys",
        "name": "Engineering document access — decoy files vs. the real target file",
        "tactic": "Collection",
        "technique_id": "T1530 / T1213",
        "technique_name": "Data from Cloud Storage / Data from Information Repositories",
        "indicators": [
            "/site2-dev5/old_notes.txt",
            "/archive/site2-eng2-maintenance.txt",
            "/engineering/deprecated_jumpbox_list.xlsx",
            "/site2-eng4/maintenance/eng4_jumpbox_access_notes.txt",
        ],
        "kql": (
            'AWSS3ServerAccess\n'
            '| where RequestURI has_any (\n'
            '    "old_notes.txt",\n'
            '    "site2-eng2-maintenance.txt",\n'
            '    "deprecated_jumpbox_list.xlsx",\n'
            '    "eng4_jumpbox_access_notes.txt")\n'
            '| extend IsTargetFile = RequestURI has "eng4_jumpbox_access_notes.txt"\n'
            '| project TimeGenerated, Operation, Requester, RequestURI, SourceIPAddress = column_ifexists("RemoteIP",""), HTTPStatus, IsTargetFile\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "The decoy retrievals are the dead-end investigative paths the exercise calls out — the real signal is IsTargetFile == true, which marks the moment the attacker actually finds the eng4 jumpbox access info.",
    },
    {
        "id": "internal-rdp-and-process-access",
        "name": "Internal pivot to site2-dev5 / site2-eng4 — RDP + process execution",
        "tactic": "Lateral Movement / Execution",
        "technique_id": "T1021.001",
        "technique_name": "Remote Services: Remote Desktop Protocol",
        "indicators": ["site2-dev5", "site2-eng4", "RDP", "EventID 4624/4625"],
        "kql": (
            'union isfuzzy=true\n'
            '    (SecurityEvent | where Computer has_any ("site2-dev5","site2-eng4")\n'
            '        and EventID in (4624,4625) and LogonType == 10),\n'
            '    (DeviceProcessEvents | where DeviceName has_any ("site2-dev5","site2-eng4")),\n'
            '    (DeviceNetworkEvents | where DeviceName has_any ("site2-dev5","site2-eng4") and RemotePort == 3389)\n'
            '| project TimeGenerated, Type,\n'
            '    Computer = coalesce(column_ifexists("Computer",""), column_ifexists("DeviceName","")),\n'
            '    Account = coalesce(column_ifexists("Account",""), column_ifexists("AccountName","")),\n'
            '    EventID = column_ifexists("EventID",""),\n'
            '    FileName = column_ifexists("FileName","")\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Filter to EventID == 4625 (failed) preceding 4624 (success) on the same account/host for the clearest evidence of the final internal pivot.",
    },
]
