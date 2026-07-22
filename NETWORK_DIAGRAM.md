# Site2 Network — 2026-07-13/14 Attack Path

Topology and attack path for the Magnolia Sunset Site2 intrusion, derived from the
MSEL timeline in `iocs.py`. Renders automatically on GitHub.

```mermaid
graph TD
    C2["External C2<br/>4 redirector domains<br/>e.g. casepilot360.com"]
    EDGE["Edge router<br/>104.53.222.2<br/>nmap scan target"]
    HR2["site2-hr2<br/>172.17.7.4<br/>initial execution — sophia.jones"]
    EXEC4["site2-exec4<br/>172.17.6.6<br/>DCOM pivot + MWUS service"]
    HR6["site2-hr6<br/>172.17.7.8<br/>scheduled task persistence"]
    WEB["site2-web<br/>172.17.1.5<br/>portscanned"]
    DC["site2-dc<br/>172.17.2.6<br/>DCSync target"]
    FILE1["site2-file1<br/>172.17.2.3<br/>DCSync source + usercpl2 service"]

    C2 --> EDGE
    EDGE -->|initial execution| HR2
    HR2 -->|T1021.003 DCOM| EXEC4
    EXEC4 -->|T1053.005 schtask| HR6
    EXEC4 -->|T1046 portscan| WEB
    EXEC4 -->|T1003.006 DCSync krbtgt| DC
    EXEC4 -->|T1135 enum + T1021.002 SMB link| FILE1

    classDef compromised fill:#f85149,stroke:#8b1a1a,color:#fff
    classDef scanned fill:#d29922,stroke:#8a5d00,color:#fff
    class HR2,EXEC4,HR6,FILE1 compromised
    class EDGE,WEB,DC scanned
```

**Legend:** red = compromised host, amber = scanned/targeted only (no confirmed code execution).

## Subnets

| Subnet | CIDR (assumed /24) | Hosts |
|---|---|---|
| HR | 172.17.7.0/24 | site2-hr2 (172.17.7.4), site2-hr6 (172.17.7.8) |
| Exec | 172.17.6.0/24 | site2-exec4 (172.17.6.6) |
| File/DC | 172.17.2.0/24 | site2-file1 (172.17.2.3), site2-dc (172.17.2.6) |
| Web | 172.17.1.0/24 | site2-web (172.17.1.5) |
| External | — | Edge router (104.53.222.2) |

CIDR boundaries are inferred from the third octet grouping the hosts share (172.17.7.x,
172.17.6.x, 172.17.2.x, 172.17.1.x) — confirm against the actual range subnet masks if
you have them; this diagram doesn't assume anything beyond what's in the MSEL timeline.
