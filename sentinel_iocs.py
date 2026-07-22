# Sentinel / Log Analytics Kusto (KQL) detection knowledge base for the
# "NorthGrid Cloud Pivot Assessment Guide" scenario: a compromised
# third-party contractor account (teddy.potts@northgrid.com) is used to pivot
# from Azure (Entra ID / Key Vault / service principals) into AWS
# (AssumeRole -> S3), ultimately hunting for access details to the Site2
# engineering jumpbox (site2-eng4) hidden among decoy files.
#
# This is assessment-guide-derived, not yet validated against live telemetry
# (no sequence/date/time — see iocs.py's Elastic side for what a
# telemetry-confirmed entry looks like, once this gets run against real
# Sentinel/Log Analytics data). Table/column choices follow the guide's own
# "Relevant Tables" call-outs per phase plus standard Sentinel/Log Analytics
# schemas for tables the guide names but doesn't detail columns for
# (MicrosoftGraphActivityLogs / AADGraphActivityLogs).

KNOWN_INFRASTRUCTURE = {
    "compromised_accounts": [
        "teddy.potts@northgrid.com",   # Phase 1 — initial contractor compromise
        "svc-northgrid-access@site2.com",  # customer-environment account reached via the pivot
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
    "s3_bucket": "site2-engineering-docs",  # named in the guide's "Identify Engineering Document Access" hunt query
    "relevant_tables": [
        "SigninLogs", "AADUserRiskEvents", "AADRiskyUsers",
        "MicrosoftGraphActivityLogs", "AADGraphActivityLogs", "AuditLogs",
        "AzureActivity", "AADServicePrincipalSignInLogs", "AADManagedIdentitySignInLogs",
        "AWSCloudTrail", "AWSGuardDuty", "AWSS3ServerAccess", "AWSVPCFlow",
        "SecurityEvent", "DeviceProcessEvents", "DeviceNetworkEvents",
    ],
}

DETECTIONS = [
    # -------------------------------------------------------------------
    # Phase 1 — Contractor Account Compromise
    # -------------------------------------------------------------------
    {
        "id": "p1-failed-signins-teddy-potts",
        "name": "Failed sign-ins for the contractor account prior to successful access",
        "tactic": "Initial Access",
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["teddy.potts@northgrid.com", "185.214.132.47", "185.214.132.88", "45.9.148.112", "91.219.236.47"],
        "kql": (
            'SigninLogs\n'
            '| where UserPrincipalName =~ "teddy.potts@northgrid.com"\n'
            '| where ResultType != "0"\n'
            '| where IPAddress in ("185.214.132.47", "185.214.132.88", "45.9.148.112", "91.219.236.47")\n'
            '| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ResultDescription, Location, AppDisplayName\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": (
            "Expect a burst of failures against one or more of the four attacker IPs immediately "
            "before a successful sign-in — classic password-spray/credential-stuffing precursor to "
            "a compromise. Drop the IPAddress filter if you want to see ALL failed sign-ins for the "
            "account (to catch attacker infrastructure not yet in the known-IP list)."
        ),
    },
    {
        "id": "p1-successful-signin-after-failures",
        "name": "Successful sign-in for contractor account from attacker infrastructure",
        "tactic": "Initial Access",
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["teddy.potts@northgrid.com", "185.214.132.47", "185.214.132.88", "45.9.148.112", "91.219.236.47"],
        "kql": (
            'SigninLogs\n'
            '| where UserPrincipalName =~ "teddy.potts@northgrid.com"\n'
            '| where ResultType == "0"\n'
            '| where IPAddress in ("185.214.132.47", "185.214.132.88", "45.9.148.112", "91.219.236.47")\n'
            '| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, RiskLevelDuringSignIn, RiskState\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "The pivot point of Phase 1 — this is the sign-in the whole rest of the attack chain hangs off of. Correlate its timestamp against the failed-sign-in burst above.",
    },
    {
        "id": "p1-risk-detections-contractor",
        "name": "Identity Protection risk detections tied to the contractor account",
        "tactic": "Initial Access",
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["teddy.potts@northgrid.com"],
        "kql": (
            'AADUserRiskEvents\n'
            '| where UserPrincipalName =~ "teddy.potts@northgrid.com"\n'
            '| project TimeGenerated, UserPrincipalName, RiskEventType, RiskLevel, RiskState, RiskDetail, Source\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Entra ID Identity Protection risk events (anomalous token, leaked credentials, unfamiliar sign-in properties, etc.) — look for a RiskEventType that lines up with the sign-in burst.",
    },
    {
        "id": "p1-elevated-risk-state",
        "name": "Contractor account flagged with elevated risk state",
        "tactic": "Initial Access",
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["teddy.potts@northgrid.com"],
        "kql": (
            'AADRiskyUsers\n'
            '| where UserPrincipalName =~ "teddy.potts@northgrid.com"\n'
            '| where RiskLevel in ("medium", "high")\n'
            '| project TimeGenerated, UserPrincipalName, RiskLevel, RiskState, RiskLastUpdatedDateTime'
        ),
        "notes": "AADRiskyUsers reflects the account's current/aggregate risk state rather than a single event — a medium/high RiskLevel here corroborates the AADUserRiskEvents findings above.",
    },
    {
        "id": "p1-impossible-travel-geo",
        "name": "Multiple geographic sign-in locations in a short window (impossible travel)",
        "tactic": "Initial Access",
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["teddy.potts@northgrid.com"],
        "kql": (
            'SigninLogs\n'
            '| where UserPrincipalName =~ "teddy.potts@northgrid.com"\n'
            '| where ResultType == "0"\n'
            '| summarize Locations = make_set(Location), IPs = make_set(IPAddress), SignInCount = count() by bin(TimeGenerated, 1h)\n'
            '| where array_length(Locations) > 1\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Bucketed by hour — more than one distinct Location in the same bucket is the impossible-travel signal the guide calls out. Narrow the bin size if you need tighter correlation.",
    },
    # -------------------------------------------------------------------
    # Phase 2 — Azure Enumeration
    # -------------------------------------------------------------------
    {
        "id": "p2-graph-enumeration",
        "name": "Microsoft Graph enumeration from the compromised account",
        "tactic": "Discovery",
        "technique_id": "T1087.004",
        "technique_name": "Account Discovery: Cloud Account",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["teddy.potts@northgrid.com", "MicrosoftGraphActivityLogs"],
        "kql": (
            'union isfuzzy=true\n'
            '  (MicrosoftGraphActivityLogs | where UserId has "teddy.potts" or IPAddress in ("185.214.132.47", "185.214.132.88", "45.9.148.112", "91.219.236.47")),\n'
            '  (AADGraphActivityLogs | where CallerIdentity has "teddy.potts" or IpAddress in ("185.214.132.47", "185.214.132.88", "45.9.148.112", "91.219.236.47"))\n'
            '| project TimeGenerated, RequestUri, RequestMethod = column_ifexists("RequestMethod", ""), ResponseStatusCode = column_ifexists("ResponseStatusCode", ""), IPAddress = column_ifexists("IPAddress", column_ifexists("IpAddress", ""))\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Look for a high volume of GET requests against /users, /groups, /servicePrincipals, /applications, /roleAssignments in RequestUri — that pattern is enumeration, not normal contractor usage.",
    },
    {
        "id": "p2-entra-object-discovery",
        "name": "Entra ID directory object discovery (users/groups/apps enumeration)",
        "tactic": "Discovery",
        "technique_id": "T1087.004",
        "technique_name": "Account Discovery: Cloud Account",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["teddy.potts@northgrid.com"],
        "kql": (
            'AuditLogs\n'
            '| where InitiatedBy has "teddy.potts"\n'
            '| where ActivityDisplayName has_any ("List", "Read", "Get")\n'
            '| project TimeGenerated, ActivityDisplayName, InitiatedBy, TargetResources, Result\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "AuditLogs captures directory-level reads that Graph activity logs sometimes miss depending on ingestion config — run both queries and cross-reference.",
    },
    {
        "id": "p2-service-principal-discovery",
        "name": "Service principal discovery/enumeration",
        "tactic": "Discovery",
        "technique_id": "T1087.004",
        "technique_name": "Account Discovery: Cloud Account",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["teddy.potts@northgrid.com", "NorthGrid-CustomerAccess-SP"],
        "kql": (
            'AuditLogs\n'
            '| where InitiatedBy has "teddy.potts"\n'
            '| where TargetResources has "servicePrincipal" or ActivityDisplayName has "service principal"\n'
            '| project TimeGenerated, ActivityDisplayName, InitiatedBy, TargetResources, Result\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "This is the step where the attacker locates NorthGrid-CustomerAccess-SP as a pivot target — cross-reference the TargetResources display name against that service principal.",
    },
    {
        "id": "p2-role-assignment-review",
        "name": "Role assignment enumeration in Azure",
        "tactic": "Discovery",
        "technique_id": "T1069.003",
        "technique_name": "Permission Groups Discovery: Cloud Groups",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["teddy.potts@northgrid.com"],
        "kql": (
            'AzureActivity\n'
            '| where Caller has "teddy.potts" or CallerIpAddress in ("185.214.132.47", "185.214.132.88", "45.9.148.112", "91.219.236.47")\n'
            '| where OperationNameValue has "roleAssignments" or OperationNameValue has "roleDefinitions"\n'
            '| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, Resource\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Microsoft.Authorization/roleAssignments/read and roleDefinitions/read operations — the attacker mapping what NorthGrid-CustomerAccess-SP and the compromised account can actually reach.",
    },
    {
        "id": "p2-keyvault-access-attempts",
        "name": "Key Vault access attempts during enumeration",
        "tactic": "Discovery",
        "technique_id": "T1526",
        "technique_name": "Cloud Service Discovery",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["teddy.potts@northgrid.com"],
        "kql": (
            'AzureActivity\n'
            '| where Caller has "teddy.potts" or CallerIpAddress in ("185.214.132.47", "185.214.132.88", "45.9.148.112", "91.219.236.47")\n'
            '| where OperationNameValue has "Microsoft.KeyVault"\n'
            '| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, Resource\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Vault-listing/reads (Microsoft.KeyVault/vaults/read) here represent the recon step before the actual secret reads in Phase 3 — expect this to precede p3-keyvault-read-success chronologically.",
    },
    # -------------------------------------------------------------------
    # Phase 3 — Cloud Credential Discovery
    # -------------------------------------------------------------------
    {
        "id": "p3-keyvault-read-failed",
        "name": "Failed Key Vault secret/key reads",
        "tactic": "Credential Access",
        "technique_id": "T1552.005",
        "technique_name": "Unsecured Credentials: Cloud Instance Metadata API (Key Vault)",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["teddy.potts@northgrid.com", "NorthGrid-CustomerAccess-SP"],
        "kql": (
            'AzureActivity\n'
            '| where OperationNameValue has "Microsoft.KeyVault/vaults/secrets"\n'
            '| where ActivityStatusValue == "Failure"\n'
            '| where Caller has "teddy.potts" or Caller has "NorthGrid-CustomerAccess-SP"\n'
            '| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, Resource'
        ),
        "notes": "Access-denied attempts on secrets the account/SP wasn't (yet) authorized for — the trial-and-error phase before landing on the secret that actually works.",
    },
    {
        "id": "p3-keyvault-read-success",
        "name": "Successful Key Vault secret read — likely AWS federation credential retrieval",
        "tactic": "Credential Access",
        "technique_id": "T1552.005",
        "technique_name": "Unsecured Credentials: Cloud Instance Metadata API (Key Vault)",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["teddy.potts@northgrid.com", "NorthGrid-CustomerAccess-SP"],
        "kql": (
            'AzureActivity\n'
            '| where OperationNameValue has "Microsoft.KeyVault/vaults/secrets"\n'
            '| where ActivityStatusValue == "Success"\n'
            '| where Caller has "teddy.potts" or Caller has "NorthGrid-CustomerAccess-SP"\n'
            '| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, Resource'
        ),
        "notes": (
            "HIGH VALUE — this is almost certainly where the AWS federation/role-assumption "
            "credentials get pulled, directly enabling Phase 4. Resource field should show which "
            "secret/vault; if it references anything AWS/role/federation-related, that's the smoking "
            "gun connecting Azure to the AWS pivot."
        ),
    },
    {
        "id": "p3-managed-identity-usage",
        "name": "Managed identity sign-in activity",
        "tactic": "Credential Access",
        "technique_id": "T1528",
        "technique_name": "Steal Application Access Token",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["NorthGrid-CustomerAccess-SP"],
        "kql": (
            'AADManagedIdentitySignInLogs\n'
            '| where IPAddress in ("185.214.132.47", "185.214.132.88", "45.9.148.112", "91.219.236.47") or ServicePrincipalName has "NorthGrid"\n'
            '| project TimeGenerated, ServicePrincipalName, ResourceDisplayName, IPAddress, ResultType\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Managed identity sign-ins from attacker-associated IPs, or against NorthGrid-named resources — a resource acquiring a token it wouldn't normally request is the signal here.",
    },
    {
        "id": "p3-service-principal-auth",
        "name": "Service principal authentication events for NorthGrid-CustomerAccess-SP",
        "tactic": "Credential Access",
        "technique_id": "T1528",
        "technique_name": "Steal Application Access Token",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["NorthGrid-CustomerAccess-SP"],
        "kql": (
            'AADServicePrincipalSignInLogs\n'
            '| where ServicePrincipalName has "NorthGrid-CustomerAccess-SP"\n'
            '| project TimeGenerated, ServicePrincipalName, AppDisplayName, ResultType, IPAddress\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Every authentication as this SP — establishes the full timeline of how long/how often the attacker rode this identity, useful for scoping blast radius.",
    },
    # -------------------------------------------------------------------
    # Phase 4 — AWS Pivot
    # -------------------------------------------------------------------
    {
        "id": "p4-assumerole-failed",
        "name": "Failed AssumeRole attempt against NorthGridEngineeringAccess",
        "tactic": "Lateral Movement",
        "technique_id": "T1550.001",
        "technique_name": "Use Alternate Authentication Material: Application Access Token",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["arn:aws:iam::482917364820:role/NorthGridEngineeringAccess", "AssumeRole"],
        "kql": (
            'AWSCloudTrail\n'
            '| where EventName == "AssumeRole"\n'
            '| where RequestParameters has "NorthGridEngineeringAccess" or ResponseElements has "NorthGridEngineeringAccess"\n'
            '| where isnotempty(ErrorCode)\n'
            '| project TimeGenerated, EventName, SourceIpAddress, UserIdentityArn, ErrorCode, ErrorMessage, RequestParameters\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "AccessDenied on the role before it succeeds — expected if the attacker's first federated credential lacked trust-policy permissions, or was still iterating.",
    },
    {
        "id": "p4-assumerole-success",
        "name": "Successful AssumeRole into NorthGridEngineeringAccess (Azure-to-AWS pivot)",
        "tactic": "Lateral Movement",
        "technique_id": "T1550.001",
        "technique_name": "Use Alternate Authentication Material: Application Access Token",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["arn:aws:iam::482917364820:role/NorthGridEngineeringAccess", "AssumeRole"],
        "kql": (
            'AWSCloudTrail\n'
            '| where EventName == "AssumeRole"\n'
            '| where RequestParameters has "NorthGridEngineeringAccess" or ResponseElements has "NorthGridEngineeringAccess"\n'
            '| where isempty(ErrorCode)\n'
            '| project TimeGenerated, EventName, SourceIpAddress, UserIdentityArn, ResponseElements\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "THE Azure-to-AWS pivot event — the whole scenario's second major hinge point after the Phase 1 initial sign-in. ResponseElements will contain the temporary credentials' AssumedRoleUser ARN/session name, useful for tracing everything downstream in CloudTrail by session.",
    },
    {
        "id": "p4-s3-enumeration",
        "name": "S3 bucket/object enumeration after AssumeRole",
        "tactic": "Discovery",
        "technique_id": "T1619",
        "technique_name": "Cloud Storage Object Discovery",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["site2-engineering-docs", "ListBucket", "ListObjects"],
        "kql": (
            'AWSCloudTrail\n'
            '| where EventName in ("ListBuckets", "ListObjects", "ListObjectsV2", "GetBucketLocation")\n'
            '| where UserIdentityArn has "NorthGridEngineeringAccess" or SourceIpAddress in ("185.214.132.47", "185.214.132.88", "45.9.148.112", "91.219.236.47")\n'
            '| project TimeGenerated, EventName, SourceIpAddress, UserIdentityArn, RequestParameters\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Look for the bucket name site2-engineering-docs appearing in RequestParameters — confirms which bucket the attacker targeted before the GetObject calls in Phase 5.",
    },
    {
        "id": "p4-engineering-doc-access-cloudtrail",
        "name": "Engineering document object access via CloudTrail (post-pivot)",
        "tactic": "Collection",
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["site2-engineering-docs", "GetObject"],
        "kql": (
            'AWSCloudTrail\n'
            '| where EventName == "GetObject"\n'
            '| where RequestParameters has "site2-engineering-docs"\n'
            '| where UserIdentityArn has "NorthGridEngineeringAccess"\n'
            '| project TimeGenerated, EventName, SourceIpAddress, UserIdentityArn, RequestParameters\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Management-plane view of object access (vs. p5 below which uses the data-plane S3 access logs) — run both, CloudTrail and S3 server access logs don't always have identical coverage depending on trail/logging config.",
    },
    # -------------------------------------------------------------------
    # Phase 5 — Engineering Documentation Discovery
    # -------------------------------------------------------------------
    {
        "id": "p5-decoy-file-access",
        "name": "Access to decoy engineering files",
        "tactic": "Collection",
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": [
            "/site2-dev5/old_notes.txt",
            "/archive/site2-eng2-maintenance.txt",
            "/engineering/deprecated_jumpbox_list.xlsx",
        ],
        "kql": (
            'AWSS3ServerAccess\n'
            '| where Operation has "GET"\n'
            '| where RequestURI has_any ("old_notes.txt", "site2-eng2-maintenance.txt", "deprecated_jumpbox_list.xlsx")\n'
            '| project TimeGenerated, Operation, Requester, RequestURI, HTTPStatus\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "These three are DEAD ENDS by design — expect them accessed in some order before the real target file below. Useful for showing the investigative path an analyst (or the attacker) actually walked, not just the end state.",
    },
    {
        "id": "p5-target-file-access",
        "name": "Access to the target file — eng4_jumpbox_access_notes.txt (mission objective)",
        "tactic": "Collection",
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["/site2-eng4/maintenance/eng4_jumpbox_access_notes.txt"],
        "kql": (
            'AWSS3ServerAccess\n'
            '| where Operation has "GET"\n'
            '| where RequestURI has "eng4_jumpbox_access_notes.txt"\n'
            '| project TimeGenerated, Operation, Requester, RequestURI, HTTPStatus\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": (
            "CRITICAL — this is the actual objective of the entire attack chain: access details for "
            "the site2-eng4 jumpbox. Everything in Phase 6 (internal RDP/access to site2-eng4) should "
            "be explainable as a direct consequence of whatever credentials/details this file "
            "contained. If you can retrieve the object itself (not just the access log line), do so — "
            "its contents tell you exactly what the attacker now knows."
        ),
    },
    {
        "id": "p5-decoy-then-target-sequence",
        "name": "Full document-access sequence: decoys followed by target file",
        "tactic": "Collection",
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["site2-engineering-docs"],
        "kql": (
            'AWSS3ServerAccess\n'
            '| where Operation has "GET"\n'
            '| where RequestURI has_any (\n'
            '    "old_notes.txt", "site2-eng2-maintenance.txt", "deprecated_jumpbox_list.xlsx",\n'
            '    "eng4_jumpbox_access_notes.txt")\n'
            '| project TimeGenerated, Operation, Requester, RequestURI, HTTPStatus\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Single timeline view combining p5-decoy-file-access and p5-target-file-access — this is the query to hand an analyst who needs to reconstruct \"what order did they open things in\" for the after-action report.",
    },
    # -------------------------------------------------------------------
    # Phase 6 — Internal Engineering Access
    # -------------------------------------------------------------------
    {
        "id": "p6-rdp-failed",
        "name": "Failed RDP attempts against site2-dev5 / site2-eng4",
        "tactic": "Lateral Movement",
        "technique_id": "T1021.001",
        "technique_name": "Remote Services: Remote Desktop Protocol",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["site2-dev5", "site2-eng4"],
        "kql": (
            'SecurityEvent\n'
            '| where Computer has_any ("site2-dev5", "site2-eng4")\n'
            '| where EventID == 4625\n'
            '| where LogonType == 10\n'
            '| project TimeGenerated, Computer, Account, IpAddress, LogonType, FailureReason\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "LogonType 10 = RemoteInteractive (RDP). Expect these immediately following the successful discovery of the target file — the attacker trying the access details it contained.",
    },
    {
        "id": "p6-rdp-success",
        "name": "Successful RDP session to site2-dev5 / site2-eng4",
        "tactic": "Lateral Movement",
        "technique_id": "T1021.001",
        "technique_name": "Remote Services: Remote Desktop Protocol",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["site2-dev5", "site2-eng4"],
        "kql": (
            'SecurityEvent\n'
            '| where Computer has_any ("site2-dev5", "site2-eng4")\n'
            '| where EventID == 4624\n'
            '| where LogonType == 10\n'
            '| project TimeGenerated, Computer, Account, IpAddress, LogonType\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "This closes the loop on the whole scenario: cloud-credential theft in Azure turning into an actual interactive session on the target internal jumpbox.",
    },
    {
        "id": "p6-process-execution",
        "name": "Process execution on site2-dev5 / site2-eng4 following RDP access",
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["site2-dev5", "site2-eng4"],
        "kql": (
            'DeviceProcessEvents\n'
            '| where DeviceName has_any ("site2-dev5", "site2-eng4")\n'
            '| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Whatever the attacker does once they're actually on the jumpbox — look for anything reading/copying files, credential tools, or further recon commands post-RDP.",
    },
    {
        "id": "p6-network-activity",
        "name": "Network activity from site2-dev5 / site2-eng4 during the intrusion window",
        "tactic": "Command and Control",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["site2-dev5", "site2-eng4"],
        "kql": (
            'DeviceNetworkEvents\n'
            '| where DeviceName has_any ("site2-dev5", "site2-eng4")\n'
            '| where RemoteIP in ("185.214.132.47", "185.214.132.88", "45.9.148.112", "91.219.236.47")\n'
            '| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Direct connections from the jumpbox back to known attacker IPs would indicate a second-stage foothold beyond just credential/file access — check even if RDP came from an internal-looking source.",
    },
    # -------------------------------------------------------------------
    # Primary Hunt Queries — broad, cross-table pivots from the guide's
    # own "Primary Hunt Queries" section. These are meant as starting
    # points for an analyst, not narrow single-technique detections.
    # -------------------------------------------------------------------
    {
        "id": "hunt-compromised-infrastructure",
        "name": "[Hunt] All activity associated with known attacker infrastructure",
        "tactic": "Command and Control",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["185.214.132.47", "185.214.132.88", "45.9.148.112", "91.219.236.47"],
        "kql": (
            'let AttackerIPs = dynamic(["185.214.132.47", "185.214.132.88", "45.9.148.112", "91.219.236.47"]);\n'
            'union isfuzzy=true\n'
            '  (SigninLogs | where IPAddress in (AttackerIPs) | extend Source = "SigninLogs", Detail = strcat(UserPrincipalName, " -> ", AppDisplayName)),\n'
            '  (AzureActivity | where CallerIpAddress in (AttackerIPs) | extend Source = "AzureActivity", Detail = strcat(Caller, " -> ", OperationNameValue)),\n'
            '  (AWSCloudTrail | where SourceIpAddress in (AttackerIPs) | extend Source = "AWSCloudTrail", Detail = strcat(UserIdentityArn, " -> ", EventName)),\n'
            '  (DeviceNetworkEvents | where RemoteIP in (AttackerIPs) | extend Source = "DeviceNetworkEvents", Detail = strcat(DeviceName, " -> ", RemoteIP, ":", tostring(RemotePort)))\n'
            '| project TimeGenerated, Source, Detail\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Expected result per the guide: a single timeline spanning Azure sign-ins, AWS access, and endpoint activity — this is the query to run first to get the shape of the whole intrusion before drilling into individual phases.",
    },
    {
        "id": "hunt-compromised-accounts",
        "name": "[Hunt] Full activity timeline for both compromised accounts",
        "tactic": "Initial Access",
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["teddy.potts@northgrid.com", "svc-northgrid-access@site2.com"],
        "kql": (
            'union isfuzzy=true\n'
            '  (SigninLogs | where UserPrincipalName in ("teddy.potts@northgrid.com", "svc-northgrid-access@site2.com") | extend Source = "SigninLogs"),\n'
            '  (AuditLogs | where InitiatedBy has_any ("teddy.potts", "svc-northgrid-access") | extend Source = "AuditLogs")\n'
            '| project TimeGenerated, Source, UserPrincipalName = column_ifexists("UserPrincipalName", ""), InitiatedBy = column_ifexists("InitiatedBy", ""), ResultType = column_ifexists("ResultType", ""), ActivityDisplayName = column_ifexists("ActivityDisplayName", "")\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Shows the progression the guide expects: contractor compromise (teddy.potts) leading into activity under the customer-environment account (svc-northgrid-access@site2.com) — the moment that second account shows up is worth flagging on its own as a privilege-boundary crossing.",
    },
    {
        "id": "hunt-service-principal-abuse",
        "name": "[Hunt] Service principal abuse timeline",
        "tactic": "Credential Access",
        "technique_id": "T1528",
        "technique_name": "Steal Application Access Token",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["NorthGrid-CustomerAccess-SP"],
        "kql": (
            'union isfuzzy=true\n'
            '  (AADServicePrincipalSignInLogs | where ServicePrincipalName has "NorthGrid-CustomerAccess-SP" | extend Source = "AADServicePrincipalSignInLogs"),\n'
            '  (AzureActivity | where Caller has "NorthGrid-CustomerAccess-SP" | extend Source = "AzureActivity"),\n'
            '  (AuditLogs | where InitiatedBy has "NorthGrid-CustomerAccess-SP" | extend Source = "AuditLogs")\n'
            '| project TimeGenerated, Source, Detail = strcat(column_ifexists("OperationNameValue", ""), column_ifexists("ActivityDisplayName", ""), column_ifexists("ResourceDisplayName", ""))\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Expected result per the guide: discovery of cloud resource access and credential retrieval — this should line up chronologically with p3-keyvault-read-success.",
    },
    {
        "id": "hunt-aws-pivot-activity",
        "name": "[Hunt] Evidence of Azure-to-AWS transition",
        "tactic": "Lateral Movement",
        "technique_id": "T1550.001",
        "technique_name": "Use Alternate Authentication Material: Application Access Token",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["NorthGridEngineeringAccess", "AssumeRole", "GetObject"],
        "kql": (
            'AWSCloudTrail\n'
            '| where EventName in ("AssumeRole", "GetObject") or RequestParameters has "NorthGridEngineeringAccess" or ResponseElements has "NorthGridEngineeringAccess"\n'
            '| project TimeGenerated, EventName, SourceIpAddress, UserIdentityArn, ErrorCode, RequestParameters\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Broad version of p4-assumerole-success + p4-engineering-doc-access-cloudtrail combined — use this first, then narrow to the specific phase queries once you've confirmed the pivot happened.",
    },
    {
        "id": "hunt-engineering-doc-access",
        "name": "[Hunt] Engineering document access timeline (decoys -> target)",
        "tactic": "Collection",
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["site2-engineering-docs"],
        "kql": (
            'AWSS3ServerAccess\n'
            '| where RequestURI has "site2-engineering-docs"\n'
            '| where Operation has "GET"\n'
            '| project TimeGenerated, Operation, Requester, RequestURI, HTTPStatus\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Same as p5-decoy-then-target-sequence but scoped by bucket name rather than enumerating filenames — use this if new/unlisted decoy files show up that aren't in the known three.",
    },
    {
        "id": "hunt-endpoint-access",
        "name": "[Hunt] Endpoint access — RDP, process execution, file access on site2-dev5/eng4",
        "tactic": "Lateral Movement",
        "technique_id": "T1021.001",
        "technique_name": "Remote Services: Remote Desktop Protocol",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["site2-dev5", "site2-eng4"],
        "kql": (
            'union isfuzzy=true\n'
            '  (SecurityEvent | where Computer has_any ("site2-dev5", "site2-eng4") | where EventID in (4624, 4625) | extend Source = "SecurityEvent"),\n'
            '  (DeviceProcessEvents | where DeviceName has_any ("site2-dev5", "site2-eng4") | extend Source = "DeviceProcessEvents"),\n'
            '  (DeviceNetworkEvents | where DeviceName has_any ("site2-dev5", "site2-eng4") | extend Source = "DeviceNetworkEvents")\n'
            '| project TimeGenerated, Source, Computer = column_ifexists("Computer", column_ifexists("DeviceName", "")), Detail = strcat(column_ifexists("EventID", ""), " ", column_ifexists("FileName", ""), " ", column_ifexists("RemoteIP", ""))\n'
            '| sort by TimeGenerated asc'
        ),
        "notes": "Expected result per the guide: RDP activity, process execution, and engineering file access, in one combined view — the last leg of the reconstructed attack path.",
    },
]
