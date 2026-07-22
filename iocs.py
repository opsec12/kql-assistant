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

CASE SENSITIVITY NOTE: process.name / file.name are ECS "keyword" fields, and
Kibana KQL matches keyword fields case-sensitively. Filenames below are mostly
lowercase by convention, but confirmed telemetry shows the real casing is
usually title-case, not lowercase. Confirmed so far:
  - "AdobeARM.exe" (not "adobearm.exe")
  - "WerCheck2.exe" (not "wercheck2.exe") — an earlier version of this file
    briefly had this wrong as "WebCheck2.exe" based on an ambiguous chat
    message; the actual file-creation event confirmed "WerCheck2.exe" is
    correct (matches the original MSEL spelling, just needed proper casing).
Also confirmed: this same payload (420,864 bytes, entropy ~3.805, identical
MZ header) has now shown up under three different names on three different
hosts (iexplorerupdate.exe on hr2, update.exe on exec4, WerCheck2.exe on
hr6) — treat size/entropy/header as the reliable fingerprint, not the name.
The remaining unconfirmed 2026-07-13/14 filenames (usercpl2.exe, update_svc.exe,
update.exe) haven't been tested against real telemetry for exact casing yet.
If a detection silently returns zero hits, verify the exact filename against
a real event before concluding the host wasn't touched.

ORDERING: each detection carries "sequence" (int) and "date"/"time" (24-hour,
local exercise time) when the exact position in the MSEL timeline is known.
Only the 2026-07-13/14 Site2 HR/Exec/File intrusion has confirmed clock times
end-to-end, so those 17 entries are numbered 1-17 in the order they happened.
The original 15 detections predate that timeline and only have loose
day-based references in the ops plan (day_-1, day_5, etc.) rather than exact
timestamps, so sequence/date/time are left as None for those rather than
guessing — the /playbook endpoint sorts sequenced entries first (in order),
then appends the unsequenced ones after.
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
        "202.84.73.50",    # NOT in original ops plan's IP list, but CONFIRMED to be
                            # casepilot360.com — a DNS query on site2-hr6 (WerCheck2.exe, Sysmon
                            # Event ID 22, 2026-07-14 22:32:15 local) resolved casepilot360.com to
                            # this exact IP. AdobeARM.exe beacons here directly by IP on site2-hr2
                            # (20:25:03 and 20:25:46 local, ~43s apart, same PID) — same C2 channel,
                            # just accessed by IP instead of domain. Likely a rotated/additional A
                            # record for the domain rather than separate infrastructure.
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
        "site2-hr2",   # 2026-07-13/14 timeline: initial execution host (sophia.jones)
        "site2-hr6",   # 2026-07-13/14 timeline: scheduled-task persistence host
        "site2-exec4", # 2026-07-13/14 timeline: DCOM lateral movement + MWUS service host
        "site2-file1", # 2026-07-13/14 timeline: DCSync target + usercpl2 service host
    ],
    # Confirmed hostname -> IP mapping for the 2026-07-13/14 timeline. Used to
    # OR host.ip alongside host.name in detections below (host.name isn't
    # always populated depending on the log source).
    "host_ip_map": {
        "site2-hr2": "172.17.7.4",
        "site2-hr6": "172.17.7.8",
        "site2-exec4": "172.17.6.6",
        "site2-file1": "172.17.2.3",
        "site2-dc": "172.17.2.6",
        "site2-web": "172.17.1.5",  # the "webserver" scanned at 22:33 — now identified by hostname
    },
    "edge_router_ip": "104.53.222.2",  # confirmed nmap scan target, 2026-07-13 21:28 ET
    "recon_scan_source_ips": [
        "103.195.145.2",  # confirmed via Zeek ssh.log (so-sensor-2): connected to the edge
                           # router 104.53.222.2:22 at 2026-07-13T21:28:42.385 ET (auth_attempts:
                           # 0 — a banner grab, not a login attempt; consistent with nmap -sV
                           # service/version detection). Timestamp matches the MSEL's "2128" entry
                           # to the second. Geolocates to Japan / AS2519 ARTERIA Networks. CAVEAT:
                           # port 22 gets constant internet-wide background-scan noise 24/7 from
                           # unrelated sources — the exact timestamp match is the main evidence
                           # this is the OPFOR scan and not coincidental noise. Corroborate by
                           # checking Zeek conn.log for other ports on 104.53.222.2 hit by this
                           # same source IP in the same window before treating it as fully confirmed.
    ],
    "known_ot_asset": {
        "host": "HMI (site2-eng4 pivot target)",
        "ip": "192.168.123.170",
        "ports_of_interest": [22, 111, 21, 20, 445, 3389],
    },
    "dropped_payload_names": [
        "adobearm.exe", "wer.exe",  # masquerading as legit filenames
        # 2026-07-13/14 timeline additions — same masquerade families reused:
        "iexplorerupdate.exe", "update.exe", "update_svc.exe", "usercpl2.exe",
        "WerCheck2.exe",  # confirmed exact casing via telemetry (title-case, matches MSEL spelling)
    ],
    "credential_theft_targets": [
        ".ssh/config",
        ".ssh/known_hosts",
        "HMI Access.txt",
        "connect-hmi.bat",
    ],
    "compromised_users": [
        "sophia.jones",  # 2026-07-13/14 timeline: initial execution on site2-hr2
        "svc_cifs",      # confirmed via Elastic Defend: used for the DCOM pivot to site2-exec4,
                          # 2026-07-14 21:11:40 — a different account than sophia.jones, meaning
                          # credentials were already stolen/reused by this point. How svc_cifs was
                          # obtained isn't confirmed in telemetry seen so far.
    ],
    # Exact on-disk paths confirmed via telemetry (vs. dropped_payload_names,
    # which is just the filename). Only populated where we've actually seen
    # a log event naming the full path — don't assume for the rest.
    "confirmed_payload_paths": {
        "AdobeARM.exe": "C:\\Users\\sophia.jones\\Downloads\\AdobeARM.exe",
    },
}
# Full detection set: one entry per TTP observed in the ops plan.
DETECTIONS = [
    {
        "id": "c2-primary-http-beacon",
        "name": "Primary HTTP/S C2 beacon to known redirector domain",
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["casepilot360.com", "port 80", "185.214.132.47", "202.84.73.50"],
        "kql": (
            '(url.domain: "casepilot360.com" or dns.question.name: "casepilot360.com" '
            'or http.request.headers.host: "casepilot360.com" or '
            'destination.ip: ("185.214.132.47" or "202.84.73.50")) and destination.port: 80'
        ),
        "notes": (
            "casepilot360.com is the primary teamserver redirector per the ops plan (day_-1 infra "
            "doc), originally documented at 185.214.132.47. CONFIRMED via Sysmon DNS query "
            "telemetry on site2-hr6 (WerCheck2.exe, 2026-07-14 22:32:15 local, Sysmon Event ID 22): "
            "casepilot360.com now resolves to 202.84.73.50 — the same IP AdobeARM.exe beaconed to "
            "directly on site2-hr2 (see c2-adobearm-first-callback). That resolves the earlier open "
            "question about whether 202.84.73.50 was separate infrastructure: it isn't, it's this "
            "same domain, either rotated to a new IP or round-robin/multi-A-record. Both IPs are "
            "now included since the original may still be live."
        ),
    },
    {
        "id": "c2-secondary-redirector-domains",
        "name": "Traffic to secondary/backup redirector domains",
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["learntocode.ai", "nvidiaupdate.tech", "eventworld.com"],
        "kql": (
            'url.domain: ("learntocode.ai" or "nvidiaupdate.tech" or "eventworld.com") '
            'or dns.question.name: ("learntocode.ai" or "nvidiaupdate.tech" or "eventworld.com")'
        ),
        "notes": (
            "Additional DNS redirector records tied to the same NAT rule set as the primary C2 "
            "domain. CHECKED, empty — unlike the other empty results in this investigation, this "
            "one is likely a genuine negative rather than a wrong field/tool assumption: the ops "
            "plan itself notes nvidiaupdate.tech/eventworld.com as \"registered (unassigned at doc "
            "time)\", and only casepilot360.com has surfaced anywhere in confirmed telemetry across "
            "the whole site2 timeline (hr6's DNS query, exec4's beacon traffic). Read as: this "
            "engagement only activated the primary redirector; the other three were reserved "
            "infrastructure that was never actually used here. Worth re-checking only if new hosts "
            "outside the currently-confirmed set (hr2/hr6/exec4/file1) turn up."
        ),
    },
    {
        "id": "c2-internal-relay",
        "name": "Internal beacon / redirector relay traffic",
        "tactic": "Command and Control",
        "technique_id": "T1090",
        "technique_name": "Proxy",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["101.96.16.8", "101.96.16.5", "101.96.16.200:8081"],
        "kql": (
            '(destination.ip: ("101.96.16.8" or "101.96.16.5") ) or '
            '(destination.ip: "101.96.16.200" and destination.port: 8081)'
        ),
        "notes": (
            "These are the internal NAT/relay addresses redirectors forward traffic to before it "
            "reaches the teamserver. CHECKED, empty — and this one's almost certainly a genuine "
            "negative rather than a wrong-field guess: this hop (redirector -> teamserver) happens "
            "entirely on attacker-controlled infrastructure behind the public redirector IP. "
            "Defender-side sensors (Zeek/Suricata) only see traffic originating from the victim "
            "hosts (172.17.x.x) out to the public redirector (casepilot360.com/202.84.73.50) — they "
            "have no visibility into what that redirector does with the traffic next. Not "
            "detectable from this vantage point regardless of query; treat as structurally "
            "unobservable, not unconfirmed."
        ),
    },
    {
        "id": "c2-spoofed-jquery-uri",
        "name": "C2 traffic disguised as jQuery library requests",
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols (Masquerading URI)",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": [
            "/jquery-3.3.1.min.js", "/jquery-3.3.2.min.js", "/info/update",
            "old IE11 user-agent on non-IE host",
        ],
        "kql": 'rule.name: "ET MALWARE Cobalt Strike Activity (POST)" or rule.uuid: "2035376"',
        "notes": (
            "The C2 profile masquerades beacon check-ins as jQuery library fetches with a "
            "hardcoded IE11-on-Win8.1 user-agent — that UA on hosts that shouldn't be running "
            "IE11 is a strong outlier signal. CONFIRMED via a real instance from site2-exec4 (see "
            "c2-beacon-exec4-jquery below) — but match on the Suricata alert itself (rule.name / "
            "sid 2035376, dataset suricata.alert) rather than reconstructing url.path + "
            "user_agent.original as raw ECS fields, which aren't reliably mapped in this "
            "environment (same lesson as the SMB pipe-field guesses elsewhere in this timeline)."
        ),
    },
    {
        "id": "c2-smb-named-pipe",
        "name": "Cobalt Strike default SMB beacon named pipe",
        "tactic": "Command and Control",
        "technique_id": "T1071.002",
        "technique_name": "Application Layer Protocol: File Transfer Protocols (SMB Beacon)",
        "sequence": None,
        "date": None,
        "time": None,
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
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": [
            "\\\\<host>\\admin$\\system32\\", "AdobeARM.exe", "wer.exe", "WerCheck2.exe",
            "svc_cifs", "process.name: System",
        ],
        "kql": (
            '(file.path: "*\\\\admin$\\\\system32\\\\*" and '
            '(file.name: ("AdobeARM.exe" or "adobearm.exe" or "wer.exe") or event.action: "file-create")) or '
            '(process.name: "System" and process.pid: 4 and user.name: "svc_cifs")'
        ),
        "notes": (
            "CONFIRMED for site2-hr6: WerCheck2.exe (see defense-evasion-wercheck2-drop) was "
            "written to C:\\windows\\system32\\ by process.name: \"System\" (PID 4) under "
            "user.name: svc_cifs — the classic telemetry signature of a remote SMB-based write "
            "(ADMIN$/C$ share), where the kernel System process performs the disk I/O on behalf "
            "of the authenticated remote user rather than a normal user-mode process appearing as "
            "the writer. Added process.name: \"System\" + pid 4 + svc_cifs as a second detection "
            "clause alongside the original path-based one. NOTE: telemetry shows site2-hr2's "
            "AdobeARM.exe actually arrived via a user download to the Downloads folder (see "
            "exec-adobearm-detonation), not ADMIN$ — so this technique applies to the later-stage "
            "hosts (confirmed: hr6; plausible but unconfirmed: exec4, file1) rather than the "
            "initial entry point."
        ),
    },
    {
        "id": "lm-wmic-remote-exec",
        "name": "Remote process execution via WMIC process call create",
        "tactic": "Lateral Movement",
        "technique_id": "T1047",
        "technique_name": "Windows Management Instrumentation",
        "sequence": None,
        "date": None,
        "time": None,
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
        "sequence": None,
        "date": None,
        "time": None,
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
        "sequence": None,
        "date": None,
        "time": None,
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
        "sequence": None,
        "date": None,
        "time": None,
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
        "sequence": None,
        "date": None,
        "time": None,
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
        "sequence": None,
        "date": None,
        "time": None,
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
        "sequence": None,
        "date": "2026-07-07",
        "time": "22:17",
        "indicators": ["192.168.123.170", "172.17.3.6", "OpenSSH_10.3p1 Debian-1"],
        "kql": (
            'destination.ip: "192.168.123.170" and destination.port: 22 and '
            'source.ip: (not "192.168.123.0/24")'
        ),
        "notes": (
            "The critical control here is the IT/OT boundary crossing itself: any SSH session "
            "into the HMI subnet originating from outside that subnet should be a near-zero-"
            "false-positive alert if the network is properly segmented.\n\n"
            "CONFIRMED via Zeek ssh.log: 2026-07-08T02:17:39.752Z UTC (~2026-07-07 22:17 local, "
            "assuming the same UTC-4 offset used elsewhere in this range) — source 172.17.3.6 "
            "(outside 192.168.123.0/24, not yet in host_ip_map, presumed site2-eng4/OT jump box "
            "given the T10 context but not confirmed by hostname in this event) to the HMI "
            "192.168.123.170:22, auth_success: true, 1 attempt. Notably this is 5-6 days before "
            "the main site2-hr2/exec4/file1 timeline (07-13/14) — reads as a separate T10 OT-pivot "
            "track from the ops plan rather than the same intrusion chain. Also worth flagging: "
            "client banner is OpenSSH_10.3p1 Debian-1 (a Linux client) against the HMI's "
            "OpenSSH_for_Windows_9.8 server — consistent with the pivot coming from attacker "
            "tooling/a Linux jump host rather than directly from a compromised Windows IT "
            "workstation, though that's an inference, not confirmed."
        ),
    },
    {
        "id": "recon-adx-enumeration",
        "name": "Remote enumeration of Azure Data Explorer (ADX) resources",
        "tactic": "Discovery / Collection",
        "technique_id": "T1526 / T1213",
        "technique_name": "Cloud Service Discovery / Data from Information Repositories",
        "sequence": None,
        "date": None,
        "time": None,
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
        "sequence": None,
        "date": None,
        "time": None,
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
    # -------------------------------------------------------------------
    # 2026-07-13 / 2026-07-14 timeline — Site2 HR/Exec/File intrusion.
    # Payload names (adobearm.exe, wer.exe-family) match the original ops
    # plan's dropped_payload_names, and the SMB link reuses the same
    # mojo.* pipe pattern — this looks like a continuation of the same
    # Magnolia Sunset Site2 exercise rather than a separate scenario.
    # Host IPs below are confirmed values from host_ip_map / edge_router_ip.
    # sequence/date/time are confirmed from the MSEL and, where noted,
    # upgraded to exact telemetry timestamps (still shown to the minute
    # in 24-hour local time to match the MSEL format).
    # -------------------------------------------------------------------
    {
        "id": "recon-nmap-scan",
        "name": "Nmap scan of edge router preceding intrusion",
        "tactic": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "sequence": 1,
        "date": "2026-07-13",
        "time": "21:28",
        "indicators": ["nmap.exe", "-sS", "-p-", "104.53.222.2", "103.195.145.2"],
        "kql": (
            '(process.name: "nmap.exe" or process.command_line: "*nmap*" or '
            'process.command_line: "*-sS*" or process.command_line: "*-p-*") or '
            '(destination.ip: "104.53.222.2" and source.ip: "103.195.145.2")'
        ),
        "notes": (
            "2026-07-13 21:28:42 ET — confirmed via Zeek ssh.log (so-sensor-2): source IP "
            "103.195.145.2 (Japan, AS2519 ARTERIA Networks) connected to the edge router "
            "104.53.222.2:22 with auth_attempts: 0 — a banner grab (SSH-2.0-OpenSSH_5.5p1 "
            "Debian-6+squeeze5), not a login attempt, consistent with nmap -sV. Timestamp matches "
            "the MSEL's \"2128\" entry to the second. Scoped the kql to this specific source.ip "
            "instead of the original bare destination.ip filter, which was noisy since the edge "
            "router sees all transit traffic. CAVEAT: SSH port 22 gets constant internet-wide "
            "background-scan noise 24/7 from unrelated sources — the exact timestamp match is the "
            "main evidence tying 103.195.145.2 to the OPFOR scan rather than coincidental noise. "
            "Check Zeek conn.log for other ports on 104.53.222.2 hit by this same source in the "
            "same window to corroborate a broader port sweep before treating it as fully confirmed."
        ),
    },
    {
        "id": "exec-adobearm-detonation",
        "name": "AdobeARM.exe detonation (initial execution)",
        "tactic": "Execution",
        "technique_id": "T1204.002",
        "technique_name": "User Execution: Malicious File",
        "sequence": 2,
        "date": "2026-07-14",
        "time": "20:25",
        "indicators": [
            "AdobeARM.exe", "C:\\Users\\sophia.jones\\Downloads\\AdobeARM.exe",
            "site2-hr2", "172.17.7.4", "sophia.jones",
        ],
        "kql": (
            '(process.name: "AdobeARM.exe" or process.executable: "*\\\\AdobeARM.exe") and '
            '(host.name: "site2-hr2" or host.ip: "172.17.7.4") and user.name: "sophia.jones"'
        ),
        "notes": (
            "2026-07-14 20:25:03 local (confirmed via Sysmon Event ID 3 on site2-hr2, PID 2520) "
            "— corrected from an earlier lowercase guess: real casing is \"AdobeARM.exe\", and KQL "
            "matches process.name (a keyword field) case-sensitively, so the original lowercase "
            "query would have silently matched nothing. Also corrects the delivery-method assumption: "
            "the file ran from C:\\Users\\sophia.jones\\Downloads\\AdobeARM.exe — a user download, "
            "not an ADMIN$ share push (that technique applies to the later exec4/hr6/file1 hosts, "
            "see lm-admin-share-upload)."
        ),
    },
    {
        "id": "defense-evasion-unsigned-adobearm",
        "name": "Unsigned AdobeARM.exe (impersonation signal)",
        "tactic": "Defense Evasion",
        "technique_id": "T1036.005",
        "technique_name": "Masquerading: Match Legitimate Name or Location",
        "sequence": None,
        "date": None,
        "time": None,
        "indicators": ["AdobeARM.exe", "process.code_signature.exists: false"],
        "kql": 'process.name: "AdobeARM.exe" and process.code_signature.exists: false',
        "notes": (
            "Not tied to a specific timeline slot — this is a durable, host-agnostic hunting rule "
            "rather than a point-in-time event, so it has no sequence number, but it corresponds to "
            "the same moment as exec-adobearm-detonation (#2). Confirmed via Elastic Defend "
            "(endpoint.events.file) on site2-hr2: the AdobeARM.exe process (PID 2520) has "
            "process.code_signature.exists: false. Real Adobe binaries are digitally signed by "
            "Adobe Inc. — an unsigned AdobeARM.exe is a strong, low-false-positive signal on its "
            "own, independent of filename or path, so this would still catch the payload if it's "
            "renamed or dropped on a different host you haven't scoped yet. Follow-up lead: this "
            "event also shows process.parent.pid: 7280, but the parent process's name/image wasn't "
            "captured in this event — pulling process-creation events for PID 7280 on site2-hr2 "
            "would identify what actually launched AdobeARM.exe (browser, email client, Explorer, "
            "etc.), which would confirm the initial delivery vector."
        ),
    },
    {
        "id": "c2-adobearm-first-callback",
        "name": "AdobeARM.exe C2 beaconing to 202.84.73.50",
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "sequence": 3,
        "date": "2026-07-14",
        "time": "20:25",
        "indicators": ["202.84.73.50", "port 80", "AdobeARM.exe", "site2-hr2", "172.17.7.4"],
        "kql": (
            '(process.name: "AdobeARM.exe" and destination.ip: "202.84.73.50" and '
            'destination.port: 80) or destination.ip: "202.84.73.50"'
        ),
        "notes": (
            "2026-07-14 20:25:03.436 local — Sysmon Event ID 3 (NetworkConnect) shows AdobeARM.exe "
            "(PID 2520, C:\\Users\\sophia.jones\\Downloads\\AdobeARM.exe) opened an outbound HTTP "
            "connection to 202.84.73.50:80 within seconds of running. CONFIRMED RECURRING: a second "
            "identical connection (same PID/ProcessGuid, new ephemeral source port 56563) followed "
            "at 20:25:46.648 local — a ~43-second interval — meaning this is an active beacon, not "
            "a one-off connection. This is a different, tighter cadence than the long-sleep pattern "
            "in beacon-jitter-anomaly (13.5hr sleep / 3-min bursts), which likely describes a later-"
            "stage or different implant — worth treating these as two distinct beaconing behaviors "
            "rather than assuming one baseline covers both. 202.84.73.50 is not one of the four "
            "redirector IPs originally documented in the ops plan, but it's NOT separate "
            "infrastructure either — CONFIRMED via a DNS query on site2-hr6 (WerCheck2.exe, "
            "Sysmon Event ID 22, 2026-07-14 22:32:15 local): casepilot360.com resolves to this "
            "exact IP. So AdobeARM.exe's callback is casepilot360.com traffic, just by IP instead "
            "of domain — see c2-primary-http-beacon, now updated to include this IP."
        ),
    },
    {
        "id": "ingress-iexplorerupdate-drop",
        "name": "iexplorerupdate.exe dropped to user temp",
        "tactic": "Command and Control",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "sequence": 4,
        "date": "2026-07-14",
        "time": "20:38",
        "indicators": [
            "iexplorerupdate.exe", "C:\\Users\\sophia.jones\\local\\temp\\", "172.17.7.4",
            "420864 bytes", "entropy 3.805", "MZ header 4d5a9000...",
        ],
        "kql": (
            'file.name: "iexplorerupdate.exe" or '
            'file.path: "*\\\\sophia.jones\\\\*\\\\Temp\\\\iexplorerupdate.exe"'
        ),
        "notes": (
            "2026-07-14 20:38:18.500 local — confirmed by TWO independent sensors: Elastic Defend "
            "(endpoint.events.file, event.action: creation) and Sysmon (see "
            "defense-evasion-timestomp-iexplorerupdate, whose PreviousCreationUtcTime field matches "
            "this timestamp almost to the millisecond) — dropped by AdobeARM.exe (PID 2520) to the "
            "exact path C:\\Users\\sophia.jones\\AppData\\Local\\Temp\\iexplorerupdate.exe (the "
            "MSEL's shorthand \"local/temp\" is AppData\\Local\\Temp). 420,864 bytes, valid PE (MZ "
            "header), entropy 3.8 — notably low for a dropped second-stage payload; typical packed/"
            "encrypted malware runs entropy 7+, so this binary likely isn't packed, which may make "
            "it easier to statically analyze if you can retrieve a copy. STRONG LINK: update.exe "
            "on site2-exec4 (see lm-dcom-to-exec4) is the exact same size (420,864 bytes), nearly "
            "identical entropy, and the same MZ header — near-certain it's this same payload "
            "reused under a different name on a different host. 13 minutes after detonation, "
            "same process still running. Name masquerades as an Internet Explorer updater "
            "(T1036.005). Add 'and host.ip: \"172.17.7.4\"' if you want "
            "to scope strictly to this host. See defense-evasion-timestomp-iexplorerupdate for the "
            "immediate follow-up event on this same file."
        ),
    },
    {
        "id": "defense-evasion-timestomp-iexplorerupdate",
        "name": "Timestomping of iexplorerupdate.exe",
        "tactic": "Defense Evasion",
        "technique_id": "T1070.006",
        "technique_name": "Indicator Removal: Timestomp",
        "sequence": 5,
        "date": "2026-07-14",
        "time": "20:38",
        "indicators": ["iexplorerupdate.exe", "AdobeARM.exe", "site2-hr2", "Sysmon Event ID 2"],
        "kql": 'event.code: "2" and event.provider: "Microsoft-Windows-Sysmon"',
        "notes": (
            "2026-07-14 20:38 local (~40 seconds after the drop) — AdobeARM.exe (PID 2520) "
            "rewrote iexplorerupdate.exe's creation timestamp from its real creation time to a "
            "fake backdated value of 2026-04-24 — almost 3 months in the past, presumably to "
            "blend the dropped file in with older, already-trusted binaries during casual triage. "
            "Sysmon Event ID 2 (FileCreateTime) is rare in normal Windows operation, so the bare "
            "event.code: \"2\" filter above is a reasonably high-fidelity hunt on its own — narrow "
            "with process.name or file.name if it's noisy in your environment. NOTE: the Sysmon "
            "config's rule.name field tags this as \"T1099\", a retired/legacy ATT&CK ID — the "
            "current mapping is T1070.006 Timestomp, used here; don't trust rule.name for ATT&CK "
            "mapping without checking the current framework. Also note this specific event shipped "
            "via a forwarder (agent.name: site2-backup, 172.17.2.9) rather than directly from "
            "site2-hr2 — confirm whether forwarded events preserve agent.name consistently in your "
            "pipeline before building detections around it."
        ),
    },
    {
        "id": "lm-dcom-to-exec4",
        "name": "DCOM lateral movement to site2-exec4",
        "tactic": "Lateral Movement",
        "technique_id": "T1021.003",
        "technique_name": "Remote Services: Distributed Component Object Model",
        "sequence": 6,
        "date": "2026-07-14",
        "time": "21:11",
        "indicators": [
            "update.exe", "C:\\Program Files (x86)\\Microsoft Works\\update.exe",
            "site2-exec4", "172.17.6.6", "powershell.exe", "svc_cifs", "420864 bytes",
        ],
        "kql": (
            'file.path: "*\\\\Microsoft Works\\\\update.exe" or '
            '(file.name: "update.exe" and (host.name: "site2-exec4" or host.ip: "172.17.6.6")) or '
            '(process.name: "powershell.exe" and user.name: "svc_cifs" and '
            '(host.name: "site2-exec4" or host.ip: "172.17.6.6")) or '
            '(process.parent.name: "mmc.exe" and (host.name: "site2-exec4" or host.ip: "172.17.6.6"))'
        ),
        "notes": (
            "2026-07-14 21:11:40 local — confirmed via Elastic Defend on site2-exec4: a signed, "
            "trusted powershell.exe (PID 6476, Microsoft-signed) wrote update.exe to "
            "C:\\Program Files (x86)\\Microsoft Works\\update.exe — masquerading via a plausible-"
            "looking but unrelated install directory (T1036.005), similar to the later System32 "
            "drop on file1. Ran under user.name: svc_cifs, NOT sophia.jones — a different, "
            "service-type account, meaning the attacker had already pivoted to different "
            "credentials by this point; how svc_cifs was obtained isn't captured in telemetry "
            "seen so far and is worth hunting for separately. STRONG LINK: this file is exactly "
            "420,864 bytes with entropy ~3.805 and the same MZ header bytes as iexplorerupdate.exe "
            "(see ingress-iexplorerupdate-drop) — near-certain this is the same payload reused "
            "across both hosts, just renamed; get a hash on both if you can pull the binaries to "
            "confirm definitively. Kept the process.parent.name: \"mmc.exe\" clause as a fallback "
            "since DCOM/MMC20.Application is the plausible mechanism, but that's still an "
            "assumption — this event's process.parent.pid is 5540 and its name wasn't captured, "
            "so confirming mmc.exe (or ruling it out in favor of WMI/another COM object) is still "
            "an open lead."
        ),
    },
    {
        "id": "defense-evasion-process-hollowing-rundll32",
        "name": "Process hollowing: update_svc.exe injects rundll32.exe",
        "tactic": "Defense Evasion / Privilege Escalation",
        "technique_id": "T1055.012",
        "technique_name": "Process Injection: Process Hollowing",
        "sequence": 7,
        "date": "2026-07-14",
        "time": "22:19",
        "indicators": [
            "update_svc.exe", "rundll32.exe", "SetThreadContext", "site2-exec4", "172.17.6.6",
            "C:\\Program Files (x86)\\Microsoft Works\\update_svc.exe",
        ],
        "kql": (
            '(process.Ext.api.name: "SetThreadContext" and '
            'process.Ext.api.behaviors: "execute_shellcode") or '
            '(process.name: "update_svc.exe" and Target.process.name: "rundll32.exe")'
        ),
        "notes": (
            "2026-07-14 22:19:09 local — confirmed via Elastic Defend's Threat Intelligence "
            "provider (endpoint.events.api, event.category: intrusion_detection) on site2-exec4: "
            "update_svc.exe (PID 8580, the MWUS service binary — see persist-mwus-service, "
            "parent.executable: services.exe, confirming it's actually running as that service, "
            "unsigned, SYSTEM integrity) spawned rundll32.exe (PID 8896) in a suspended state and "
            "called SetThreadContext on it targeting unbacked/shellcode memory (RCX: Unbacked, "
            "RDX: Data). This is classic process hollowing — the MWUS service isn't just "
            "persistence, it's actively injecting into a fresh, legitimate-looking rundll32.exe to "
            "run the real payload somewhere with a clean on-disk process image, presumably to blend "
            "with normal living-off-the-land rundll32 usage. This likely explains how exec4 carries "
            "out its later remote actions (schtask install on hr6, portscan of site2-web, "
            "enumeration of file1, DCSync) — worth checking whether those originate from this "
            "injected rundll32.exe (PID 8896 or its descendants) rather than update_svc.exe "
            "directly. Sequenced at 22:19, one minute before the MSEL's rounded \"2220\" service-"
            "start time — we don't yet have the actual service-start event, so this doesn't "
            "necessarily mean the MSEL time is wrong, just that injection happens fast once the "
            "service is running."
        ),
    },
    {
        "id": "persist-mwus-service",
        "name": "MWUS service (update_svc.exe) persistence on site2-exec4",
        "tactic": "Persistence",
        "technique_id": "T1543.003",
        "technique_name": "Create or Modify System Process: Windows Service",
        "sequence": 8,
        "date": "2026-07-14",
        "time": "22:20",
        "indicators": ["update_svc.exe", "MWUS", "site2-exec4", "172.17.6.6"],
        "kql": (
            '(process.name: "update_svc.exe" or process.command_line: "*MWUS*") and '
            '(host.name: "site2-exec4" or host.ip: "172.17.6.6")'
        ),
        "notes": "2026-07-14 22:20 — Windows service literally named \"MWUS\" installed to run update_svc.exe on 172.17.6.6.",
    },
    {
        "id": "persist-schtask-hr6",
        "name": "Scheduled task installed on site2-hr6 (mechanism UNCONFIRMED)",
        "tactic": "Persistence",
        "technique_id": "T1053.005",
        "technique_name": "Scheduled Task/Job: Scheduled Task",
        "sequence": 9,
        "date": "2026-07-14",
        "time": "22:27",
        "indicators": ["schtasks.exe", "/create", "site2-hr6", "172.17.7.8", "System32\\Tasks"],
        "kql": (
            '((process.name: "schtasks.exe" and process.command_line: "*/create*") or '
            '(process.name: "powershell.exe" and process.command_line: '
            '("*ScheduledTask*" or "*schtasks*")) or '
            'file.path: "*\\\\System32\\\\Tasks\\\\*" or event.code: "4698") and '
            '(host.name: "site2-hr6" or host.ip: "172.17.7.8")'
        ),
        "notes": (
            "2026-07-14 22:27 (MSEL time, not yet confirmed via telemetry) — UNCONFIRMED: the "
            "original assumption (a literal schtasks.exe /create process on hr6) has been tested "
            "against real telemetry and returns zero hits. Also tried: file writes under "
            "System32\\Tasks, and a broad host-only query filtering out trusted/signed processes — "
            "both came back empty or only surfaced unrelated noise (a signed Firefox installer "
            "event that happened to land in the same minute). Given the confirmed pattern elsewhere "
            "in this timeline — DCOM used signed powershell.exe rather than an obvious tool, and "
            "the MWUS service process-hollows rather than acting plainly — the real mechanism here "
            "is likely also non-obvious: candidates are (a) PowerShell's Register-ScheduledTask "
            "cmdlet, (b) a REMOTE schtasks.exe /s site2-hr6 /create invocation run FROM site2-exec4 "
            "(172.17.6.6) rather than on hr6 itself, in which case hr6 would show no schtasks.exe "
            "process at all — check exec4 for this. The kql above ORs together every mechanism "
            "tried so far plus Security Event 4698 as a catch-all, but none of these clauses have "
            "an confirmed hit yet — treat this as a hunting starting point, not a validated "
            "detection, until a real match is found. Also double-check the Kibana time range "
            "covers 2026-07-14 22:00-23:00 local before ruling anything out on 'zero results' "
            "alone. Precedes the WerCheck2.exe drop/execution by ~5 minutes on the same host, per the "
            "MSEL — likely the registration half of the same install-then-run sequence, whatever "
            "the actual mechanism turns out to be."
        ),
    },
    {
        "id": "defense-evasion-wercheck2-drop",
        "name": "WerCheck2.exe dropped to site2-hr6",
        "tactic": "Defense Evasion",
        "technique_id": "T1036.005",
        "technique_name": "Masquerading: Match Legitimate Name or Location",
        "sequence": 10,
        "date": "2026-07-14",
        "time": "22:31",
        "indicators": [
            "WerCheck2.exe", "C:\\windows\\system32\\WerCheck2.exe", "site2-hr6", "172.17.7.8",
            "svc_cifs", "420864 bytes",
        ],
        "kql": 'file.name: "WerCheck2.exe" and (host.name: "site2-hr6" or host.ip: "172.17.7.8")',
        "notes": (
            "2026-07-14 22:31:16 local — CORRECTED BACK: confirmed via the actual Elastic Defend "
            "file-creation event that the real spelling is \"WerCheck2.exe\" (capital W and C, "
            "matching the original MSEL text) — a previous update here mistakenly changed this to "
            "\"WebCheck2.exe\" based on an ambiguous chat message that was almost certainly a typo. "
            "This event is the authoritative source: it's the actual event.action: creation record. "
            "So this WAS just a casing issue after all (kql previously used all-lowercase "
            "\"wercheck2.exe\", real value is title-case \"WerCheck2.exe\"), same pattern as "
            "AdobeARM.exe — the Windows Error Reporting masquerade theory is back in play. Dropped "
            "to C:\\windows\\system32\\WerCheck2.exe — masquerading via System32 location, same "
            "trick as the later usercpl2.exe drop on file1. STRONG LINK: 420,864 bytes, entropy "
            "~3.805, same MZ header as iexplorerupdate.exe and update.exe — this is now the THIRD "
            "host where this exact payload shows up under a different name; treat size+entropy+"
            "header as the real fingerprint, not the filename. NOTABLE: process.name is \"System\" "
            "(PID 4) rather than a normal user process, with user.name: svc_cifs — this is the "
            "classic signature of a remote SMB-based file write (ADMIN$/C$ share), where the kernel "
            "System process performs the on-disk write on behalf of an authenticated remote user. "
            "This confirms the lm-admin-share-upload (T1021.002 ADMIN$) detection theory for this "
            "host specifically, and confirms svc_cifs (see compromised_users) is being reused as "
            "the lateral-movement credential beyond just the exec4 DCOM pivot."
        ),
    },
    {
        "id": "exec-wercheck2-schtask",
        "name": "WerCheck2 scheduled task execution",
        "tactic": "Execution",
        "technique_id": "T1053.005",
        "technique_name": "Scheduled Task/Job: Scheduled Task",
        "sequence": 11,
        "date": "2026-07-14",
        "time": "22:32",
        "indicators": ["WerCheck2.exe", "site2-hr6", "172.17.7.8", "casepilot360.com", "202.84.73.50"],
        "kql": (
            '(process.name: "WerCheck2.exe" or process.command_line: "*WerCheck2*" or '
            '(dns.question.name: "casepilot360.com" and process.name: "WerCheck2.exe")) and '
            '(host.name: "site2-hr6" or host.ip: "172.17.7.8")'
        ),
        "notes": (
            "2026-07-14 22:32:15.418 local — CONFIRMED executing and beaconing: Sysmon Event ID 22 "
            "(DNS query) shows WerCheck2.exe (PID 1628, C:\\Windows\\System32\\WerCheck2.exe) "
            "resolved casepilot360.com to 202.84.73.50 and connected. This closes the loop on the "
            "\"unconfirmed IP\" question from c2-adobearm-first-callback — 202.84.73.50 IS "
            "casepilot360.com — and confirms WerCheck2.exe is the same beacon family as "
            "AdobeARM.exe/iexplorerupdate.exe/update.exe (same fingerprint, see "
            "defense-evasion-wercheck2-drop), now proven to actually run and phone home rather "
            "than just sit on disk. Fires about a minute after the confirmed 22:31:16 drop."
        ),
    },
    {
        "id": "discovery-webserver-portscan",
        "name": "Portscan of site2-web (from site2-hr6)",
        "tactic": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "sequence": 12,
        "date": "2026-07-14",
        "time": "22:33",
        "indicators": ["site2-web", "172.17.1.5", "site2-hr6", "172.17.7.8", "icmp"],
        "kql": (
            '(destination.ip: "172.17.1.5" and source.ip: "172.17.7.8") or '
            'destination.ip: "172.17.1.5" or host.name: "site2-web"'
        ),
        "notes": (
            "2026-07-14 22:33:30.419 local — CONFIRMED SOURCE: Zeek conn.log shows the scan "
            "originates from site2-hr6 (172.17.7.8), not site2-exec4 — correcting an earlier "
            "assumption. Makes sense chronologically: WerCheck2.exe on hr6 had just confirmed-"
            "executed and beaconed one minute earlier (see exec-wercheck2-schtask), so this is "
            "likely that beacon carrying out a C2-tasked scan, not exec4. First observed packet is "
            "ICMP (ping/host-discovery, type 8 echo request) with orig_pkts: 2, resp_pkts: 0 — "
            "site2-web didn't reply to the ping, which would make a default nmap host-discovery "
            "scan report the host as down unless run with -Pn. A single ICMP event doesn't confirm "
            "an actual port scan by itself — pull additional conn.log entries for source.ip: "
            "\"172.17.7.8\" and destination.ip: \"172.17.1.5\" in the following few seconds/minutes "
            "to see the actual TCP ports probed, if any. Still no single-event signature for the "
            "scan pattern itself — look for one source.ip touching many distinct destination.port "
            "values in a short window."
        ),
    },
    {
        "id": "discovery-file1-enum",
        "name": "Enumeration of site2-file1 from site2-exec4",
        "tactic": "Discovery",
        "technique_id": "T1135",
        "technique_name": "Network Share Discovery",
        "sequence": 13,
        "date": "2026-07-14",
        "time": "22:38",
        "indicators": ["site2-exec4", "172.17.6.6", "site2-file1", "172.17.2.3", "445", "SMB"],
        "kql": 'source.ip: "172.17.6.6" and destination.ip: "172.17.2.3" and destination.port: 445',
        "notes": (
            "2026-07-14 22:38 — enumeration from the already-compromised exec4 host (172.17.6.6) "
            "targeting file1 (172.17.2.3), one minute before the DCSync. CONFIRMED query: the "
            "process-command-line guess (\"*net view*\") returned nothing — consistent with this "
            "actor's pattern of using PowerShell/native cmdlets instead of the obvious CLI tool "
            "rather than a literal net.exe invocation. Detecting at the network layer instead "
            "(SMB, destination.port 445) sidesteps that guesswork entirely and is tool-agnostic: "
            "any enumeration method (net view, Get-ChildItem, Get-SmbShare, Explorer, WMI) has to "
            "open this connection to reach the share."
        ),
    },
    {
        "id": "cred-dcsync-krbtgt",
        "name": "DCSync against krbtgt",
        "tactic": "Credential Access",
        "technique_id": "T1003.006",
        "technique_name": "OS Credential Dumping: DCSync",
        "sequence": 14,
        "date": "2026-07-14",
        "time": "22:39",
        "indicators": ["krbtgt", "lsadump::dcsync", "site2-dc", "172.17.2.6"],
        "kql": (
            'process.command_line: ("*dcsync*" or "*lsadump::dcsync*" or "*/user:krbtgt*") or '
            'event.action: ("directory-service-replication" or "replicating-directory-changes") or '
            '(destination.ip: "172.17.2.6" and event.category: "network")'
        ),
        "notes": (
            "2026-07-14 22:39 — highest-severity single event in this timeline; a golden-ticket-"
            "capable credential theft against the domain controller, site2-dc (172.17.2.6). The "
            "destination.ip clause will be noisy on its own (the DC receives constant legitimate "
            "traffic) — treat it as a supporting signal, not primary. If Windows Security auditing "
            "is mapped into ECS, also check event.code: \"4662\" for the Get-Replication-Changes-"
            "All extended right."
        ),
    },
    {
        "id": "defense-evasion-usercpl2-drop",
        "name": "usercpl2.exe dropped to System32 on site2-file1",
        "tactic": "Defense Evasion",
        "technique_id": "T1036.005",
        "technique_name": "Masquerading: Match Legitimate Name or Location",
        "sequence": 15,
        "date": "2026-07-14",
        "time": "22:48",
        "indicators": ["usercpl2.exe", "System32", "site2-file1", "172.17.2.3", "svc_cifs"],
        "kql": (
            'file.path: "C:\\\\windows\\\\system32\\\\usercpl2.exe" and event.action: "creation" '
            'and host.name: "site2-file1"'
        ),
        "notes": (
            "CONFIRMED, but timestamp corrected: actual file creation is 22:48:03 local "
            "(dataset logs-endpoint.events.file), not the MSEL's 22:41 — third timestamp "
            "correction in this timeline (after portscan and file1-enum). event.action: "
            "\"creation\", process.name \"System\" (pid 4) / user svc_cifs — that's expected/"
            "benign-looking for a file written over an SMB share, not itself suspicious; the "
            "content (a 420KB unsigned exe with MZ header, entropy ~3.8) is what makes it "
            "malicious. Note: an SMB directory-open on windows\\system32 shows up in the Zeek "
            "smb_files.log a few seconds earlier under the same session uid as the file1-enum "
            "step — that's just directory traversal in the same session, not the drop itself; "
            "use this endpoint file-creation event as the authoritative timestamp, not that one."
        ),
    },
    {
        "id": "persist-usercpl2-service",
        "name": "usercpl2 service creation on site2-file1",
        "tactic": "Persistence",
        "technique_id": "T1543.003",
        "technique_name": "Create or Modify System Process: Windows Service",
        "sequence": 16,
        "date": "2026-07-14",
        "time": "22:43",
        "indicators": ["User CPL", "usercpl2exe", "7045", "site2-file1", "172.17.2.3", "svc_cifs"],
        "kql": 'event.code: "7045" and host.name: "site2-file1"',
        "notes": (
            "CONFIRMED via Service Control Manager event 7045 (System channel), not a sc.exe/"
            "PowerShell command line — same pattern as prior steps: the real artifact is a "
            "structured OS log event, not a process command-line string. ServiceName \"User CPL\", "
            "ImagePath \"C:\\\\windows\\\\system32\\\\usercpl2exe\" (note: no literal \".exe\" "
            "separator in the ImagePath field as logged), AccountName LocalSystem, actor user "
            "svc_cifs. Timestamp 22:43:02 local — close to MSEL's 22:42 guess, one of the few "
            "steps where the MSEL time held up.\n\n"
            "IMPORTANT SEQUENCING NOTE: this service-creation event (22:43:02) is BEFORE the "
            "confirmed usercpl2.exe file-creation event (22:48:03, see defense-evasion-usercpl2-"
            "drop). So the real order was service-stub-created-first, then binary dropped 5 "
            "minutes later — the reverse of the MSEL's stated drop-then-service sequence. This "
            "means the next step's MSEL timestamp (22:47 for service execution) is now known to "
            "be wrong too, since it predates the binary's existence — the real service-start must "
            "be after 22:48:03. Search forward from there, not at 22:47."
        ),
    },
    {
        "id": "exec-usercpl2-service-start",
        "name": "usercpl2 service execution on site2-file1",
        "tactic": "Execution",
        "technique_id": "T1569.002",
        "technique_name": "System Services: Service Execution",
        "sequence": 17,
        "date": "2026-07-14",
        "time": "22:48",
        "indicators": [
            "usercpl2.exe", "site2-file1", "172.17.2.3", "services.exe",
            "31594eb9ca3ab182ee1ab6de7b29e0395926b970c347d61520fc54b89bc56b77",
            "0166beb8d0413a944d83dce604cda0c8",
        ],
        "kql": (
            'process.name: "usercpl2.exe" and event.category: "process" and '
            'event.action: "start" and host.name: "site2-file1"'
        ),
        "notes": (
            "CONFIRMED, timestamp corrected: 22:48:15.542 local — canonical process start/end "
            "event (dataset endpoint.events.process, event.action: [start, end]), 1 second before "
            "the SetThreadContext hollowing call (22:48:16.627, see defense-evasion-usercpl2-hollow-"
            "rundll32) on the same PID (4588). Not the MSEL's 22:47, which predates the binary "
            "existing at all (see persist-usercpl2-service note). parent.executable: services.exe, "
            "parent code_signature trusted/Microsoft Windows Publisher — confirms SCM legitimately "
            "launched it as the installed service; usercpl2.exe itself is unsigned, SYSTEM "
            "integrity, created_suspended: true (it's about to hollow rundll32.exe). Hashes: SHA256 "
            "31594eb9ca3ab182ee1ab6de7b29e0395926b970c347d61520fc54b89bc56b77, imphash "
            "0166beb8d0413a944d83dce604cda0c8 — good pivot IOCs for hunting this binary elsewhere."
        ),
    },
    {
        "id": "defense-evasion-usercpl2-hollow-rundll32",
        "name": "Process hollowing: usercpl2.exe injects rundll32.exe on site2-file1",
        "tactic": "Defense Evasion / Privilege Escalation",
        "technique_id": "T1055.012",
        "technique_name": "Process Injection: Process Hollowing",
        "sequence": 17,
        "date": "2026-07-14",
        "time": "22:48",
        "indicators": [
            "usercpl2.exe", "rundll32.exe", "SetThreadContext", "site2-file1", "172.17.2.3",
            "C:\\Windows\\System32\\usercpl2.exe",
        ],
        "kql": (
            '(process.Ext.api.name: "SetThreadContext" and '
            'process.Ext.api.behaviors: "execute_shellcode") or '
            '(process.name: "usercpl2.exe" and Target.process.name: "rundll32.exe")'
        ),
        "notes": (
            "CONFIRMED — 2026-07-14 22:48:16 local, via Elastic Defend's Threat Intelligence "
            "provider (endpoint.events.api, event.category: intrusion_detection) on site2-file1: "
            "usercpl2.exe (PID 4588, parent services.exe — confirms it's running as the installed "
            "\"User CPL\" service, unsigned, SYSTEM integrity) spawned rundll32.exe (PID 4460) in a "
            "suspended state and called SetThreadContext targeting unbacked/shellcode memory (RCX: "
            "Unbacked, RDX: Data). Identical technique and ECS signature to the MWUS service on "
            "exec4 (see defense-evasion-process-hollowing-rundll32) — same actor tradecraft reused "
            "on a second host: the dropped service binary is a loader, not the payload; it hollows "
            "a fresh rundll32.exe to run the real second-stage code. Not called out as its own step "
            "in the MSEL, but confirmed independently the same way the exec4 instance was."
        ),
    },
    {
        "id": "lm-smb-link-file1",
        "name": "Beacon link to site2-file1 from site2-exec4",
        "tactic": "Lateral Movement",
        "technique_id": "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "sequence": 18,
        "date": "2026-07-14",
        "time": "22:48",
        "indicators": ["site2-exec4", "172.17.6.6", "site2-file1", "172.17.2.3", "RSTO", "gssapi,smb,ntlm"],
        "kql": (
            'source.ip: "172.17.6.6" and destination.ip: "172.17.2.3" and '
            'event.dataset: "zeek.conn"'
        ),
        "notes": (
            "CONFIRMED, but not via the named-pipe guess (\"mojo.*\"/IPC$) — that field structure "
            "doesn't exist in this schema (Zeek conn/smb_files, not smb.pipe.name/smb.share). The "
            "real signature is a connection-level anomaly: a single TCP session, exec4:50233 -> "
            "file1:445 (service gssapi,smb,ntlm), starting 2026-07-14 22:48:18 local — 2 seconds "
            "after the process-hollowing call (defense-evasion-usercpl2-hollow-rundll32). Duration "
            "139148s (~38.6 hours), ~39.7MB across ~755k packets, conn_state RSTO (exec4 sent the "
            "RST that ended it). That duration/volume is wildly disproportionate to ordinary admin-"
            "share browsing (the enum/browse/drop events found earlier were single small file-opens) "
            "— consistent with a persistent SMB-tunneled beacon relay riding the same admin-share "
            "session rather than a distinct named-pipe artifact. uid Ch18GN2OihtTN5rIY7, community_id "
            "1:dX2BBJe/yykaASuEXWMEuHMJ4oU= for pivoting to related records."
        ),
    },
    {
        "id": "c2-beacon-exec4-jquery",
        "name": "C2 beacon check-in from site2-exec4 to casepilot360.com",
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols (Masquerading URI)",
        "sequence": 19,
        "date": "2026-07-14",
        "time": "22:59",
        "indicators": [
            "site2-exec4", "172.17.6.6", "casepilot360.com", "202.84.73.50",
            "jquery-3.3.2.min.js", "sid:2035376",
        ],
        "kql": 'rule.name: "ET MALWARE Cobalt Strike Activity (POST)" and source.ip: "172.17.6.6"',
        "notes": (
            "CONFIRMED — 2026-07-14 22:59:59 local, Suricata alert (dataset suricata.alert, sid "
            "2035376, \"ET MALWARE Cobalt Strike Activity (POST)\"). exec4 (172.17.6.6:51060) POSTs "
            "directly to casepilot360.com (202.84.73.50:80, Host header confirms the domain), URI "
            "/jquery-3.3.2.min.js?__cfduid=..., with the same hardcoded IE11-on-Win8.1 user-agent "
            "documented in c2_uri_patterns/suspicious_user_agent. This is exec4 running its own "
            "external C2 beacon in parallel with everything it was doing to file1 (enum, drop, "
            "hollowing, the long-lived SMB relay) — the host is talking to both the external "
            "teamserver and relaying/tunneling to a second internal host at the same time. Suricata "
            "flagged it live (event.severity_label: high) but action: allowed, so it wasn't blocked."
        ),
    },
]
