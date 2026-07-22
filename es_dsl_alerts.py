"""
Elasticsearch Query DSL alert definitions — CONFIRMED detections only.

Every entry below corresponds 1:1 to an iocs.py entry whose notes contain a
CONFIRMED finding backed by an actual telemetry event pulled during this
investigation (Zeek, Suricata, Sysmon, or Elastic Defend). Anything still
marked UNCONFIRMED in iocs.py (persist-schtask-hr6, cred-dcsync-krbtgt,
c2-internal-relay, c2-secondary-redirector-domains, c2-smb-named-pipe) is
deliberately excluded — these are real, evidenced abnormalities, not
hypotheses.

Each "query" value is a ready-to-use Elasticsearch Query DSL object — paste
it directly into Kibana's Stack Management > Rules > Create rule >
"Elasticsearch query" rule type (params.esQuery), or wrap it in a Watcher
input.search.request.body for a classic Watcher alert. Field-type notes:
  - IP fields (source.ip/destination.ip) use "term" — ES's native `ip` type
    supports exact values AND CIDR notation in a term query.
  - Numeric fields (destination.port) use "term" with an integer, not string.
  - String fields assumed keyword-mapped per standard ECS (host.name,
    process.name, file.name, file.path, event.action/category/code/dataset,
    user.name, rule.name, dns.question.name). If your data stream maps any
    of these as analyzed text instead, switch to "<field>.keyword" or
    "match_phrase" — same lesson learned the hard way with KQL throughout
    this investigation (see iocs.py's SMB pipe-name / raw HTTP field notes).
  - Wildcards use the "wildcard" query type against the (assumed-keyword)
    field directly.

severity / risk_score are heuristic, roughly following Elastic's own
detection-rule conventions (low/medium/high/critical, 21-99), weighted by
how far into the kill chain each step sits and how much autonomy it grants
the actor (e.g. process hollowing and service persistence score higher than
initial recon).
"""

CONFIRMED_ALERTS = [
    {
        "id": "recon-nmap-scan",
        "name": "[Site2] Recon scan of edge router preceding intrusion",
        "tactic": "Discovery",
        "technique_id": "T1046",
        "severity": "low",
        "risk_score": 21,
        "source_ioc_id": "recon-nmap-scan",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"source.ip": "103.195.145.2"}},
                    {"term": {"destination.ip": "104.53.222.2"}},
                    {"term": {"destination.port": 22}},
                ]
            }
        },
        "notes": "2026-07-13 21:28:42 ET — SSH banner-grab (auth_attempts: 0) against the edge router, confirmed via Zeek ssh.log.",
    },
    {
        "id": "exec-adobearm-detonation",
        "name": "[Site2] AdobeARM.exe initial execution on site2-hr2",
        "tactic": "Execution",
        "technique_id": "T1204.002",
        "severity": "high",
        "risk_score": 73,
        "source_ioc_id": "exec-adobearm-detonation",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"process.name": "AdobeARM.exe"}},
                    {"term": {"user.name": "sophia.jones"}},
                    {
                        "bool": {
                            "should": [
                                {"term": {"host.name": "site2-hr2"}},
                                {"term": {"host.ip": "172.17.7.4"}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                ]
            }
        },
        "notes": "2026-07-14 20:25:03 local — Sysmon Event ID 3, PID 2520, ran from C:\\Users\\sophia.jones\\Downloads\\.",
    },
    {
        "id": "defense-evasion-unsigned-adobearm",
        "name": "[Site2] Unsigned AdobeARM.exe (masquerade signal)",
        "tactic": "Defense Evasion",
        "technique_id": "T1036.005",
        "severity": "high",
        "risk_score": 70,
        "source_ioc_id": "defense-evasion-unsigned-adobearm",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"process.name": "AdobeARM.exe"}},
                    {"term": {"process.code_signature.exists": False}},
                ]
            }
        },
        "notes": "Host/path-agnostic hunting rule — real Adobe binaries are signed, so this catches renamed/relocated copies of the same payload too.",
    },
    {
        "id": "c2-adobearm-first-callback",
        "name": "[Site2] AdobeARM.exe C2 beacon to 202.84.73.50",
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "severity": "high",
        "risk_score": 75,
        "source_ioc_id": "c2-adobearm-first-callback",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"process.name": "AdobeARM.exe"}},
                    {"term": {"destination.ip": "202.84.73.50"}},
                    {"term": {"destination.port": 80}},
                ]
            }
        },
        "notes": "2026-07-14 20:25:03.436 local — first of a recurring ~43s-interval beacon (Sysmon Event ID 3, PID 2520).",
    },
    {
        "id": "ingress-iexplorerupdate-drop",
        "name": "[Site2] iexplorerupdate.exe dropped to user Temp",
        "tactic": "Command and Control",
        "technique_id": "T1105",
        "severity": "high",
        "risk_score": 73,
        "source_ioc_id": "ingress-iexplorerupdate-drop",
        "query": {
            "bool": {
                "should": [
                    {"term": {"file.name": "iexplorerupdate.exe"}},
                    {
                        "wildcard": {
                            "file.path": "*\\\\sophia.jones\\\\*\\\\Temp\\\\iexplorerupdate.exe"
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        },
        "notes": "2026-07-14 20:38:18.500 local — dropped by AdobeARM.exe (PID 2520). 420,864 bytes, entropy ~3.805, same fingerprint reused as update.exe (exec4) and WerCheck2.exe (hr6).",
    },
    {
        "id": "defense-evasion-timestomp-iexplorerupdate",
        "name": "[Site2] Timestomp of iexplorerupdate.exe (Sysmon FileCreateTime)",
        "tactic": "Defense Evasion",
        "technique_id": "T1070.006",
        "severity": "medium",
        "risk_score": 47,
        "source_ioc_id": "defense-evasion-timestomp-iexplorerupdate",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.code": "2"}},
                    {"term": {"event.provider": "Microsoft-Windows-Sysmon"}},
                ]
            }
        },
        "notes": "2026-07-14 20:38 local — Sysmon Event ID 2 is rare in normal operation; narrow with process.name/file.name if noisy.",
    },
    {
        "id": "lm-dcom-to-exec4",
        "name": "[Site2] DCOM lateral movement to site2-exec4",
        "tactic": "Lateral Movement",
        "technique_id": "T1021.003",
        "severity": "high",
        "risk_score": 78,
        "source_ioc_id": "lm-dcom-to-exec4",
        "query": {
            "bool": {
                "should": [
                    {"wildcard": {"file.path": "*\\\\Microsoft Works\\\\update.exe"}},
                    {
                        "bool": {
                            "filter": [
                                {"term": {"file.name": "update.exe"}},
                                {
                                    "bool": {
                                        "should": [
                                            {"term": {"host.name": "site2-exec4"}},
                                            {"term": {"host.ip": "172.17.6.6"}},
                                        ],
                                        "minimum_should_match": 1,
                                    }
                                },
                            ]
                        }
                    },
                    {
                        "bool": {
                            "filter": [
                                {"term": {"process.name": "powershell.exe"}},
                                {"term": {"user.name": "svc_cifs"}},
                                {
                                    "bool": {
                                        "should": [
                                            {"term": {"host.name": "site2-exec4"}},
                                            {"term": {"host.ip": "172.17.6.6"}},
                                        ],
                                        "minimum_should_match": 1,
                                    }
                                },
                            ]
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        },
        "notes": "2026-07-14 21:11:40 local — signed powershell.exe (PID 6476) wrote update.exe under user.name svc_cifs, not sophia.jones. Same 420,864-byte payload as iexplorerupdate.exe.",
    },
    {
        "id": "defense-evasion-process-hollowing-rundll32",
        "name": "[Site2] Process hollowing: update_svc.exe injects rundll32.exe (exec4)",
        "tactic": "Defense Evasion / Privilege Escalation",
        "technique_id": "T1055.012",
        "severity": "critical",
        "risk_score": 90,
        "source_ioc_id": "defense-evasion-process-hollowing-rundll32",
        "query": {
            "bool": {
                "should": [
                    {
                        "bool": {
                            "filter": [
                                {"term": {"process.Ext.api.name": "SetThreadContext"}},
                                {"term": {"process.Ext.api.behaviors": "execute_shellcode"}},
                            ]
                        }
                    },
                    {
                        "bool": {
                            "filter": [
                                {"term": {"process.name": "update_svc.exe"}},
                                {"term": {"Target.process.name": "rundll32.exe"}},
                            ]
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        },
        "notes": "2026-07-14 22:19:09 local — Elastic Defend Threat Intelligence provider, PID 8580 -> suspended rundll32.exe PID 8896, target memory Unbacked/Data.",
    },
    {
        "id": "persist-mwus-service",
        "name": "[Site2] MWUS service (update_svc.exe) persistence on exec4",
        "tactic": "Persistence",
        "technique_id": "T1543.003",
        "severity": "high",
        "risk_score": 80,
        "source_ioc_id": "persist-mwus-service",
        "query": {
            "bool": {
                "filter": [
                    {
                        "bool": {
                            "should": [
                                {"term": {"process.name": "update_svc.exe"}},
                                {"wildcard": {"process.command_line": "*MWUS*"}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                    {
                        "bool": {
                            "should": [
                                {"term": {"host.name": "site2-exec4"}},
                                {"term": {"host.ip": "172.17.6.6"}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                ]
            }
        },
        "notes": "2026-07-14 22:20 — Windows service literally named MWUS running update_svc.exe.",
    },
    {
        "id": "defense-evasion-wercheck2-drop",
        "name": "[Site2] WerCheck2.exe dropped to System32 on hr6",
        "tactic": "Defense Evasion",
        "technique_id": "T1036.005",
        "severity": "high",
        "risk_score": 76,
        "source_ioc_id": "defense-evasion-wercheck2-drop",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"file.name": "WerCheck2.exe"}},
                    {
                        "bool": {
                            "should": [
                                {"term": {"host.name": "site2-hr6"}},
                                {"term": {"host.ip": "172.17.7.8"}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                ]
            }
        },
        "notes": "2026-07-14 22:31:16 local — process.name System (PID 4), user.name svc_cifs: classic remote SMB/ADMIN$ write signature. Same 420,864-byte payload family (3rd host).",
    },
    {
        "id": "exec-wercheck2-schtask",
        "name": "[Site2] WerCheck2.exe execution and C2 beacon on hr6",
        "tactic": "Execution",
        "technique_id": "T1053.005",
        "severity": "high",
        "risk_score": 78,
        "source_ioc_id": "exec-wercheck2-schtask",
        "query": {
            "bool": {
                "filter": [
                    {
                        "bool": {
                            "should": [
                                {"term": {"process.name": "WerCheck2.exe"}},
                                {"wildcard": {"process.command_line": "*WerCheck2*"}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                    {
                        "bool": {
                            "should": [
                                {"term": {"host.name": "site2-hr6"}},
                                {"term": {"host.ip": "172.17.7.8"}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                ]
            }
        },
        "notes": "2026-07-14 22:32:15.418 local — Sysmon Event ID 22 DNS query, PID 1628, resolved casepilot360.com to 202.84.73.50.",
    },
    {
        "id": "discovery-webserver-portscan",
        "name": "[Site2] Portscan of site2-web sourced from hr6",
        "tactic": "Discovery",
        "technique_id": "T1046",
        "severity": "medium",
        "risk_score": 47,
        "source_ioc_id": "discovery-webserver-portscan",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"source.ip": "172.17.7.8"}},
                    {"term": {"destination.ip": "172.17.1.5"}},
                ]
            }
        },
        "notes": "2026-07-14 22:33:30.419 local — Zeek conn.log, ICMP echo request. Source corrected from an earlier exec4 assumption to hr6.",
    },
    {
        "id": "discovery-file1-enum",
        "name": "[Site2] SMB enumeration of file1 from exec4",
        "tactic": "Discovery",
        "technique_id": "T1135",
        "severity": "medium",
        "risk_score": 55,
        "source_ioc_id": "discovery-file1-enum",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"source.ip": "172.17.6.6"}},
                    {"term": {"destination.ip": "172.17.2.3"}},
                    {"term": {"destination.port": 445}},
                ]
            }
        },
        "notes": "2026-07-14 22:38 — tool-agnostic network-layer detection (Zeek smb_files.log); catches net view, Get-ChildItem, Get-SmbShare, WMI, Explorer alike.",
    },
    {
        "id": "defense-evasion-usercpl2-drop",
        "name": "[Site2] usercpl2.exe dropped to System32 on file1",
        "tactic": "Defense Evasion",
        "technique_id": "T1036.005",
        "severity": "high",
        "risk_score": 76,
        "source_ioc_id": "defense-evasion-usercpl2-drop",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"file.path": "C:\\\\windows\\\\system32\\\\usercpl2.exe"}},
                    {"term": {"event.action": "creation"}},
                    {"term": {"host.name": "site2-file1"}},
                ]
            }
        },
        "notes": "2026-07-14 22:48:03 local (MSEL said 22:41 — corrected). process.name System / user svc_cifs, 420,864 bytes, MZ header, entropy ~3.805.",
    },
    {
        "id": "persist-usercpl2-service",
        "name": "[Site2] usercpl2 (User CPL) service installed on file1",
        "tactic": "Persistence",
        "technique_id": "T1543.003",
        "severity": "high",
        "risk_score": 80,
        "source_ioc_id": "persist-usercpl2-service",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.code": "7045"}},
                    {"term": {"host.name": "site2-file1"}},
                ]
            }
        },
        "notes": "2026-07-14 22:43:02 local — SCM event 7045, ServiceName 'User CPL', ImagePath usercpl2exe, AccountName LocalSystem. Preceded the file drop by 5 minutes (service stub created first).",
    },
    {
        "id": "exec-usercpl2-service-start",
        "name": "[Site2] usercpl2.exe service execution on file1",
        "tactic": "Execution",
        "technique_id": "T1569.002",
        "severity": "high",
        "risk_score": 78,
        "source_ioc_id": "exec-usercpl2-service-start",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"process.name": "usercpl2.exe"}},
                    {"term": {"event.category": "process"}},
                    {"term": {"event.action": "start"}},
                    {"term": {"host.name": "site2-file1"}},
                ]
            }
        },
        "notes": "2026-07-14 22:48:15.542 local (MSEL said 22:47 — corrected; predates the binary's own existence at that time). Parent services.exe, unsigned, SYSTEM integrity. SHA256 31594eb9ca3ab182ee1ab6de7b29e0395926b970c347d61520fc54b89bc56b77.",
    },
    {
        "id": "defense-evasion-usercpl2-hollow-rundll32",
        "name": "[Site2] Process hollowing: usercpl2.exe injects rundll32.exe (file1)",
        "tactic": "Defense Evasion / Privilege Escalation",
        "technique_id": "T1055.012",
        "severity": "critical",
        "risk_score": 90,
        "source_ioc_id": "defense-evasion-usercpl2-hollow-rundll32",
        "query": {
            "bool": {
                "should": [
                    {
                        "bool": {
                            "filter": [
                                {"term": {"process.Ext.api.name": "SetThreadContext"}},
                                {"term": {"process.Ext.api.behaviors": "execute_shellcode"}},
                            ]
                        }
                    },
                    {
                        "bool": {
                            "filter": [
                                {"term": {"process.name": "usercpl2.exe"}},
                                {"term": {"Target.process.name": "rundll32.exe"}},
                            ]
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        },
        "notes": "2026-07-14 22:48:16.627 local — identical technique/ECS signature to the exec4/MWUS hollowing; same actor tradecraft reused on a second host.",
    },
    {
        "id": "lm-smb-link-file1",
        "name": "[Site2] Anomalous long-lived SMB session exec4 -> file1 (beacon relay)",
        "tactic": "Lateral Movement",
        "technique_id": "T1021.002",
        "severity": "high",
        "risk_score": 72,
        "source_ioc_id": "lm-smb-link-file1",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"source.ip": "172.17.6.6"}},
                    {"term": {"destination.ip": "172.17.2.3"}},
                    {"term": {"event.dataset": "zeek.conn"}},
                ]
            }
        },
        "notes": "2026-07-14 22:48:18 local — 139,148s duration (~38.6h), ~39.7MB/~755k packets, conn_state RSTO. Consider adding a duration/byte-volume range filter (e.g. event.duration > 3600) to isolate the anomaly from ordinary admin-share traffic on this same port/host pair.",
    },
    {
        "id": "c2-beacon-exec4-jquery",
        "name": "[Site2] exec4 external C2 beacon to casepilot360.com (jQuery masquerade)",
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "severity": "critical",
        "risk_score": 85,
        "source_ioc_id": "c2-beacon-exec4-jquery",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"source.ip": "172.17.6.6"}},
                    {
                        "bool": {
                            "should": [
                                {
                                    "term": {
                                        "rule.name": "ET MALWARE Cobalt Strike Activity (POST)"
                                    }
                                },
                                {"term": {"rule.uuid": "2035376"}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                ]
            }
        },
        "notes": "2026-07-14 22:59:59 local — Suricata alert, exec4:51060 -> 202.84.73.50:80, Host header casepilot360.com, action allowed (not blocked). exec4 ran this in parallel with the file1 SMB relay.",
    },
    {
        "id": "lm-ssh-to-ot-hmi",
        "name": "SSH pivot from IT-side host into OT HMI subnet",
        "tactic": "Lateral Movement",
        "technique_id": "T1021.004",
        "severity": "critical",
        "risk_score": 88,
        "source_ioc_id": "lm-ssh-to-ot-hmi",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"destination.ip": "192.168.123.170"}},
                    {"term": {"destination.port": 22}},
                ],
                "must_not": [{"term": {"source.ip": "192.168.123.0/24"}}],
            }
        },
        "notes": "2026-07-08 02:17:39 UTC (~2026-07-07 22:17 local) — source 172.17.3.6 (Linux OpenSSH_10.3p1 client) to HMI OpenSSH_for_Windows_9.8, auth_success true. Separate T10 track, ~6 days before the main hr2/exec4/file1 chain. Any hit here should be treated as near-zero-false-positive if the IT/OT boundary is properly segmented.",
    },
    {
        "id": "lm-admin-share-upload",
        "name": "[Site2] File write to ADMIN$ share via System/svc_cifs (lateral tool transfer)",
        "tactic": "Lateral Movement",
        "technique_id": "T1021.002",
        "severity": "high",
        "risk_score": 74,
        "source_ioc_id": "lm-admin-share-upload",
        "query": {
            "bool": {
                "should": [
                    {
                        "bool": {
                            "filter": [
                                {"wildcard": {"file.path": "*\\\\admin$\\\\system32\\\\*"}},
                                {
                                    "bool": {
                                        "should": [
                                            {
                                                "terms": {
                                                    "file.name": [
                                                        "AdobeARM.exe",
                                                        "adobearm.exe",
                                                        "wer.exe",
                                                    ]
                                                }
                                            },
                                            {"term": {"event.action": "file-create"}},
                                        ],
                                        "minimum_should_match": 1,
                                    }
                                },
                            ]
                        }
                    },
                    {
                        "bool": {
                            "filter": [
                                {"term": {"process.name": "System"}},
                                {"term": {"process.pid": 4}},
                                {"term": {"user.name": "svc_cifs"}},
                            ]
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        },
        "notes": "Confirmed for hr6 (WerCheck2.exe) — process.name System (PID 4) + user.name svc_cifs is the classic remote-SMB-write fingerprint. Plausible but unconfirmed on exec4/file1.",
    },
    {
        "id": "c2-primary-http-beacon",
        "name": "[Site2] HTTP beacon to primary redirector casepilot360.com",
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "severity": "high",
        "risk_score": 75,
        "source_ioc_id": "c2-primary-http-beacon",
        "query": {
            "bool": {
                "filter": [
                    {
                        "bool": {
                            "should": [
                                {"term": {"dns.question.name": "casepilot360.com"}},
                                {
                                    "terms": {
                                        "destination.ip": [
                                            "185.214.132.47",
                                            "202.84.73.50",
                                        ]
                                    }
                                },
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                    {"term": {"destination.port": 80}},
                ]
            }
        },
        "notes": "casepilot360.com resolves to 202.84.73.50 (confirmed via hr6's Sysmon DNS query); 185.214.132.47 is the original ops-plan IP, kept in case it's still live. Only casepilot360.com of the 4 planned redirectors was actually used.",
    },
]

# A single composite "any confirmed indicator" alert — fires if ANY of the
# per-technique queries above match. Good for one top-level Kibana
# "Elasticsearch query" rule watching the whole confirmed campaign at once;
# use the per-detection entries above individually when you need to know
# *which* stage fired.
MASTER_ALERT = {
    "id": "site2-campaign-any-confirmed-indicator",
    "name": "[Site2] Any confirmed campaign indicator (composite)",
    "query": {
        "bool": {
            "should": [a["query"] for a in CONFIRMED_ALERTS],
            "minimum_should_match": 1,
        }
    },
}


def to_kibana_es_query_rule(alert, index_pattern="logs-*", interval="5m", threshold=0):
    """
    Wrap one of the alerts above into a Kibana Alerting API create-rule body
    for the built-in ".es-query" (Elasticsearch query) rule type. POST this
    to /api/alerting/rule (Kibana) with the usual kbn-xsrf header.
    threshold=0 means "alert on any match >0"; adjust per rule as needed.
    """
    import json

    return {
        "name": alert["name"],
        "rule_type_id": ".es-query",
        "consumer": "alerts",
        "schedule": {"interval": interval},
        "params": {
            "searchType": "esQuery",
            "esQuery": json.dumps({"query": alert["query"]}),
            "index": [index_pattern],
            "timeField": "@timestamp",
            "size": 100,
            "thresholdComparator": ">",
            "threshold": [threshold],
            "timeWindowSize": 5,
            "timeWindowUnit": "m",
        },
        "tags": [alert["tactic"], alert["technique_id"], "site2-confirmed"],
    }
