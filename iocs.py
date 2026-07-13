"""
Engagement-specific detection knowledge base for KQL Assistant.

Built from the red team MSEL / operational plan for exercise "Magnolia Sunset
Site2 2026" (PCTE range). This is defensive content only: known adversary
infrastructure and TTPs, mapped to MITRE ATT&CK, with ready-to-run
Elasticsearch KQL hunting queries so a blue team can detect the OPFOR
activity described in the ops plan.

Nothing here contains live/real-world malicious infrastructure — these are
range/lab indicators (Cobalt Strike teamserver, redirectors, simulated OT
jump box) from a training exercise.
"""

# Known adversary-controlled / range infrastructure pulled from the ops plan.
# Injected into the LLM system prompt so freeform questions ("find the beacon
# domains", "what talks to the redirector") resolve against real exercise data.
KNOWN_INFRASTRUCTURE = {
    "c2_domains": [
        "casepilot360.com",   # primary HTTP teamserver redirector, port 80
        "learntocode.ai",     # secondary redirector, port 443
        "nvidiaupdate.tech",  # registered redirector domain (unassigned at doc time)
        "eventworld.com",     # registered redirector domain (unassigned at doc time)
    ],
    "c2_public_ips": [
        "45.83.172.91",    # learntocode.ai
        "185.214.132.47",  # casepilot360.com
        "103.197.58.214",  # nvidiaupdate.tech
        "91.209.18.166",   # eventworld.com
    ],
    "c2_internal_relay_ips": [
        "101.96.16.8",   # NAT translation target for all redirector domains
        "101.96.16.5",   # internal redirector / web delivery + C2 rewrite target
        "101.96.16.200", # internal HTTP beacon host reported in-range, port 8081
    ],
    "smb_pipe_pattern": "mojo.*",  # Cobalt Strike default SMB beacon pipename prefix
    "suspicious_user_agent": "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
    "c2_uri_patterns": [
        "/jquery-3.3.1.min.js*",
        "/jquery-3.3.1.slim.min.js*",
        "/jquery-3.3.2.min.js*",
        "/info/update*",
    ],
    "known_lateral_movement_targets": [
        "site2-dev5",  # T8
        "site2-dc",
        "site2-eng4",  # T10, OT jump box
        "site2-hr3",
    ],
    "known_ot_asset": {
        "host": "HMI (site2-eng4 pivot target)",
        "ip": "192.168.123.170",
        "ports_of_interest": [22, 111, 21, 20, 445, 3389],
    },
    "dropped_payload_names": ["adobearm.exe", "wer.exe"],  # masquerading as legit filenames
    "credential_theft_targets": [
        ".ssh/config",
        ".ssh/known_hosts",
        "HMI Access.txt",
        "connect-hmi.bat",
    ],
}

# Full detection set: one entry per TTP observed in the ops plan.
DETECTIONS = [
    {
        "id": "c2-primary-http-beacon",
        "name": "Primary HTTP/S C2 beacon to known redirector domain",
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "indicators": ["casepilot360.com", "port 80"],
        "kql": (
            '(url.domain: "casepilot360.com" or dns.question.name: "casepilot360.com" '
            'or http.request.headers.host: "casepilot360.com") and destination.port: 80'
        ),
        "notes": "casepilot360.com is the primary teamserver redirector per the ops plan (day_-1 infra doc).",
    },
    {
        "id": "c2-secondary-redirector-domains",
        "name": "Traffic to secondary/backup redirector domains",
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "indicators": ["learntocode.ai", "nvidiaupdate.tech", "eventworld.com"],
        "kql": (
            'url.domain: ("learntocode.ai" or "nvidiaupdate.tech" or "eventworld.com") '
            'or dns.question.name: ("learntocode.ai" or "nvidiaupdate.tech" or "eventworld.com")'
        ),
        "notes": "Additional DNS redirector records tied to the same NAT rule set as the primary C2 domain.",
    },
    {
        "id": "c2-internal-relay",
        "name": "Internal beacon / redirector relay traffic",
        "tactic": "Command and Control",
        "technique_id": "T1090",
        "technique_name": "Proxy",
        "indicators": ["101.96.16.8", "101.96.16.5", "101.96.16.200:8081"],
        "kql": (
            '(destination.ip: ("101.96.16.8" or "101.96.16.5") ) or '
            '(destination.ip: "101.96.16.200" and destination.port: 8081)'
        ),
        "notes": "These are the internal NAT/relay addresses redirectors forward traffic to before it reaches the teamserver.",
    },
    {
        "id": "c2-spoofed-jquery-uri",
        "name": "C2 traffic disguised as jQuery library requests",
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols (Masquerading URI)",
        "indicators": [
            "/jquery-3.3.1.min.js", "/jquery-3.3.2.min.js", "/info/update",
            "old IE11 user-agent on non-IE host",
        ],
        "kql": (
            'url.path: ("/jquery-3.3.1.min.js*" or "/jquery-3.3.1.slim.min.js*" or '
            '"/jquery-3.3.2.min.js*" or "/info/update*") and '
            'user_agent.original: "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"'
        ),
        "notes": (
            "The C2 profile masquerades beacon check-ins as jQuery library fetches with a "
            "hardcoded IE11-on-Win8.1 user-agent — that UA on hosts that shouldn't be running "
            "IE11 is a strong outlier signal."
        ),
    },
    {
        "id": "c2-smb-named-pipe",
        "name": "Cobalt Strike default SMB beacon named pipe",
        "tactic": "Command and Control",
        "technique_id": "T1071.002",
        "technique_name": "Application Layer Protocol: File Transfer Protocols (SMB Beacon)",
        "indicators": ["named pipe prefix: mojo.*"],
        "kql": (
            'smb.pipe.name: "mojo.*" or smb.share: "mojo.*" or file.path: "*\\\\pipe\\\\mojo.*"'
        ),
        "notes": (
            "Cobalt Strike's default SMB beacon pipename generator uses a 'mojo.NNNN.NNNN...' "
            "pattern unless the operator overrides it. Named-pipe telemetry usually needs "
            "Sysmon Event ID 17/18 (PipeEvent) ingested into Elastic to populate these fields — "
            "confirm your pipe-name field mapping if this comes back empty."
        ),
    },
    {
        "id": "lm-admin-share-upload",
        "name": "File write to ADMIN$ share (lateral tool transfer)",
        "tactic": "Lateral Movement",
        "technique_id": "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "indicators": ["\\\\<host>\\admin$\\system32\\", "adobearm.exe", "wer.exe"],
        "kql": (
            'file.path: "*\\\\admin$\\\\system32\\\\*" and '
            '(file.name: ("adobearm.exe" or "wer.exe") or event.action: "file-create")'
        ),
        "notes": "Both observed payload drops used ADMIN$ upload followed by WMIC remote execution.",
    },
    {
        "id": "lm-wmic-remote-exec",
        "name": "Remote process execution via WMIC process call create",
        "tactic": "Lateral Movement",
        "technique_id": "T1047",
        "technique_name": "Windows Management Instrumentation",
        "indicators": ["wmic /node:", "process call create", "cmd.exe /c start"],
        "kql": (
            'process.name: "wmic.exe" and process.command_line: ("*process call create*" and "*/node:*")'
        ),
        "notes": "Used for both T8 (site2-dev5) and T10 (site2-eng4, OT jump box) lateral movement in the plan.",
    },
    {
        "id": "persist-wmi-event-subscription",
        "name": "WMI Event Subscription persistence (filter/consumer/binding)",
        "tactic": "Persistence",
        "technique_id": "T1546.003",
        "technique_name": "Event Triggered Execution: WMI Event Subscription",
        "indicators": ["__EventFilter", "CommandLineEventConsumer", "__FilterToConsumerBinding"],
        "kql": (
            'process.name: "powershell.exe" and process.command_line: '
            '("*__EventFilter*" or "*CommandLineEventConsumer*" or "*__FilterToConsumerBinding*" '
            'or "*Set-WmiInstance*")'
        ),
        "notes": "Matches the boot-triggered persistence script in the day_5 plan almost verbatim.",
    },
    {
        "id": "exec-encoded-powershell",
        "name": "Base64-encoded PowerShell execution",
        "tactic": "Execution / Defense Evasion",
        "technique_id": "T1059.001 / T1027",
        "technique_name": "PowerShell / Obfuscated Files or Information",
        "indicators": ["powershell -encodedcommand", "-enc", "-e "],
        "kql": (
            'process.name: "powershell.exe" and process.command_line: '
            '("*-encodedcommand*" or "*-enc *" or "* -e *")'
        ),
        "notes": (
            "Cheap but high-value: legitimate encoded PowerShell is rare outside of software "
            "installers/config management. Pair with a baseline of your known-good automation "
            "tools (Terraform provisioners, GitLab runners, etc.) to cut false positives."
        ),
    },
    {
        "id": "cred-theft-ssh-and-plaintext-files",
        "name": "Access/exfil of SSH credential material and plaintext credential files",
        "tactic": "Credential Access",
        "technique_id": "T1552.001",
        "technique_name": "Unsecured Credentials: Credentials In Files",
        "indicators": [".ssh/config", ".ssh/known_hosts", "HMI Access.txt", "connect-hmi.bat"],
        "kql": (
            'file.path: ("*\\\\.ssh\\\\config*" or "*\\\\.ssh\\\\known_hosts*" or '
            '"*HMI Access.txt*" or "*connect-hmi.bat*") and '
            'event.action: ("file-open" or "file-access" or "file-read")'
        ),
        "notes": (
            "In the plan, these specific filenames on the OT engineer's workstation directly "
            "led to the HMI compromise — a filename-based canary/detection here is disproportionately "
            "high value for an OT environment."
        ),
    },
    {
        "id": "discovery-local-recon",
        "name": "Local host/network discovery command chain",
        "tactic": "Discovery",
        "technique_id": "T1018 / T1049 / T1016",
        "technique_name": "Remote System Discovery / System Network Connections & Config Discovery",
        "indicators": ["arp -a", "netstat -ano", "ipconfig /all"],
        "kql": (
            'process.name: ("arp.exe" or "netstat.exe" or "ipconfig.exe") and '
            'process.parent.name: ("cmd.exe" or "powershell.exe" or "wmic.exe")'
        ),
        "notes": "Low signal alone (used constantly by admins) — weight higher when chained after a WMIC remote-exec event on the same host within a short window.",
    },
    {
        "id": "discovery-ot-portscan",
        "name": "Port scan against OT/HMI host",
        "tactic": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "indicators": ["192.168.123.170", "ports 22,111,21,20,445,3389"],
        "kql": (
            'destination.ip: "192.168.123.170" and destination.port: (22 or 111 or 21 or 20 or 445 or 3389) '
            'and network.direction: "outbound"'
        ),
        "notes": "Any scan pattern touching the HMI's port range from a non-engineering-workstation source is high fidelity in an OT segment.",
    },
    {
        "id": "lm-ssh-to-ot-hmi",
        "name": "SSH pivot from IT-side host into OT HMI",
        "tactic": "Lateral Movement",
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "indicators": ["192.168.123.170", "ssh clara@192.168.123.170"],
        "kql": (
            'destination.ip: "192.168.123.170" and destination.port: 22 and '
            'source.ip: (not "192.168.123.0/24")'
        ),
        "notes": (
            "The critical control here is the IT/OT boundary crossing itself: any SSH session "
            "into the HMI subnet originating from outside that subnet should be a near-zero-"
            "false-positive alert if the network is properly segmented."
        ),
    },
    {
        "id": "recon-adx-enumeration",
        "name": "Remote enumeration of Azure Data Explorer (ADX) resources",
        "tactic": "Discovery / Collection",
        "technique_id": "T1526 / T1213",
        "technique_name": "Cloud Service Discovery / Data from Information Repositories",
        "indicators": ["ADX query API access", "OT/HMI-related dataset access"],
        "kql": (
            'event.dataset: "azure.activitylogs" and azure.activitylogs.operation_name: '
            '"*Microsoft.Kusto*" and azure.activitylogs.identity: (not "*known-service-principal*")'
        ),
        "notes": (
            "This step is cloud-side (Azure control plane), not host/network telemetry — needs "
            "Azure Activity Log / ADX diagnostic logs shipped into Elastic. Field names above are "
            "indicative; confirm against your actual azure-native-elastic-integration mapping."
        ),
    },
    {
        "id": "beacon-jitter-anomaly",
        "name": "Long-sleep-then-fast-callback beacon interval anomaly",
        "tactic": "Command and Control",
        "technique_id": "T1029 (related) / Anomaly Detection",
        "technique_name": "Scheduled Transfer (interval anomaly)",
        "indicators": ["13.5hr sleep then 3-minute callback cadence"],
        "kql": None,
        "notes": (
            "Not a single-query detection — this is a statistical/ML signal: build a per-host "
            "beacon-interval baseline (e.g. bucket connection timestamps to the same destination "
            "and look for a long dormant gap immediately followed by a tight, regular callback "
            "cadence). This is exactly the kind of false-positive-reduction signal work described "
            "in your resume's CACI bullet — worth building as a follow-on Elastic ML job or "
            "Isolation Forest model rather than a static KQL query."
        ),
    },
]
