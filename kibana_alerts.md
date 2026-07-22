# Site2 Confirmed Detections — Elasticsearch Query DSL Alerts

Kibana "Elasticsearch query" alert rules (Stack Management > Rules > Create rule > Elasticsearch query) for every CONFIRMED finding in this investigation. Anything still marked UNCONFIRMED in iocs.py is excluded.

**Total confirmed alerts:** 22

---

## Composite alert (any confirmed indicator)

**[Site2] Any confirmed campaign indicator (composite)**

Fires if ANY of the 22 per-technique queries below match. Use this as one top-level rule watching the whole confirmed campaign; use the individual rules when you need to know which stage fired.

```json
{
  "bool": {
    "should": [
      {
        "bool": {
          "filter": [
            {
              "term": {
                "source.ip": "103.195.145.2"
              }
            },
            {
              "term": {
                "destination.ip": "104.53.222.2"
              }
            },
            {
              "term": {
                "destination.port": 22
              }
            }
          ]
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "process.name": "AdobeARM.exe"
              }
            },
            {
              "term": {
                "user.name": "sophia.jones"
              }
            },
            {
              "bool": {
                "should": [
                  {
                    "term": {
                      "host.name": "site2-hr2"
                    }
                  },
                  {
                    "term": {
                      "host.ip": "172.17.7.4"
                    }
                  }
                ],
                "minimum_should_match": 1
              }
            }
          ]
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "process.name": "AdobeARM.exe"
              }
            },
            {
              "term": {
                "process.code_signature.exists": false
              }
            }
          ]
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "process.name": "AdobeARM.exe"
              }
            },
            {
              "term": {
                "destination.ip": "202.84.73.50"
              }
            },
            {
              "term": {
                "destination.port": 80
              }
            }
          ]
        }
      },
      {
        "bool": {
          "should": [
            {
              "term": {
                "file.name": "iexplorerupdate.exe"
              }
            },
            {
              "wildcard": {
                "file.path": "*\\\\sophia.jones\\\\*\\\\Temp\\\\iexplorerupdate.exe"
              }
            }
          ],
          "minimum_should_match": 1
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "event.code": "2"
              }
            },
            {
              "term": {
                "event.provider": "Microsoft-Windows-Sysmon"
              }
            }
          ]
        }
      },
      {
        "bool": {
          "should": [
            {
              "wildcard": {
                "file.path": "*\\\\Microsoft Works\\\\update.exe"
              }
            },
            {
              "bool": {
                "filter": [
                  {
                    "term": {
                      "file.name": "update.exe"
                    }
                  },
                  {
                    "bool": {
                      "should": [
                        {
                          "term": {
                            "host.name": "site2-exec4"
                          }
                        },
                        {
                          "term": {
                            "host.ip": "172.17.6.6"
                          }
                        }
                      ],
                      "minimum_should_match": 1
                    }
                  }
                ]
              }
            },
            {
              "bool": {
                "filter": [
                  {
                    "term": {
                      "process.name": "powershell.exe"
                    }
                  },
                  {
                    "term": {
                      "user.name": "svc_cifs"
                    }
                  },
                  {
                    "bool": {
                      "should": [
                        {
                          "term": {
                            "host.name": "site2-exec4"
                          }
                        },
                        {
                          "term": {
                            "host.ip": "172.17.6.6"
                          }
                        }
                      ],
                      "minimum_should_match": 1
                    }
                  }
                ]
              }
            }
          ],
          "minimum_should_match": 1
        }
      },
      {
        "bool": {
          "should": [
            {
              "bool": {
                "filter": [
                  {
                    "term": {
                      "process.Ext.api.name": "SetThreadContext"
                    }
                  },
                  {
                    "term": {
                      "process.Ext.api.behaviors": "execute_shellcode"
                    }
                  }
                ]
              }
            },
            {
              "bool": {
                "filter": [
                  {
                    "term": {
                      "process.name": "update_svc.exe"
                    }
                  },
                  {
                    "term": {
                      "Target.process.name": "rundll32.exe"
                    }
                  }
                ]
              }
            }
          ],
          "minimum_should_match": 1
        }
      },
      {
        "bool": {
          "filter": [
            {
              "bool": {
                "should": [
                  {
                    "term": {
                      "process.name": "update_svc.exe"
                    }
                  },
                  {
                    "wildcard": {
                      "process.command_line": "*MWUS*"
                    }
                  }
                ],
                "minimum_should_match": 1
              }
            },
            {
              "bool": {
                "should": [
                  {
                    "term": {
                      "host.name": "site2-exec4"
                    }
                  },
                  {
                    "term": {
                      "host.ip": "172.17.6.6"
                    }
                  }
                ],
                "minimum_should_match": 1
              }
            }
          ]
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "file.name": "WerCheck2.exe"
              }
            },
            {
              "bool": {
                "should": [
                  {
                    "term": {
                      "host.name": "site2-hr6"
                    }
                  },
                  {
                    "term": {
                      "host.ip": "172.17.7.8"
                    }
                  }
                ],
                "minimum_should_match": 1
              }
            }
          ]
        }
      },
      {
        "bool": {
          "filter": [
            {
              "bool": {
                "should": [
                  {
                    "term": {
                      "process.name": "WerCheck2.exe"
                    }
                  },
                  {
                    "wildcard": {
                      "process.command_line": "*WerCheck2*"
                    }
                  }
                ],
                "minimum_should_match": 1
              }
            },
            {
              "bool": {
                "should": [
                  {
                    "term": {
                      "host.name": "site2-hr6"
                    }
                  },
                  {
                    "term": {
                      "host.ip": "172.17.7.8"
                    }
                  }
                ],
                "minimum_should_match": 1
              }
            }
          ]
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "source.ip": "172.17.7.8"
              }
            },
            {
              "term": {
                "destination.ip": "172.17.1.5"
              }
            }
          ]
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "source.ip": "172.17.6.6"
              }
            },
            {
              "term": {
                "destination.ip": "172.17.2.3"
              }
            },
            {
              "term": {
                "destination.port": 445
              }
            }
          ]
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "file.path": "C:\\\\windows\\\\system32\\\\usercpl2.exe"
              }
            },
            {
              "term": {
                "event.action": "creation"
              }
            },
            {
              "term": {
                "host.name": "site2-file1"
              }
            }
          ]
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "event.code": "7045"
              }
            },
            {
              "term": {
                "host.name": "site2-file1"
              }
            }
          ]
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "process.name": "usercpl2.exe"
              }
            },
            {
              "term": {
                "event.category": "process"
              }
            },
            {
              "term": {
                "event.action": "start"
              }
            },
            {
              "term": {
                "host.name": "site2-file1"
              }
            }
          ]
        }
      },
      {
        "bool": {
          "should": [
            {
              "bool": {
                "filter": [
                  {
                    "term": {
                      "process.Ext.api.name": "SetThreadContext"
                    }
                  },
                  {
                    "term": {
                      "process.Ext.api.behaviors": "execute_shellcode"
                    }
                  }
                ]
              }
            },
            {
              "bool": {
                "filter": [
                  {
                    "term": {
                      "process.name": "usercpl2.exe"
                    }
                  },
                  {
                    "term": {
                      "Target.process.name": "rundll32.exe"
                    }
                  }
                ]
              }
            }
          ],
          "minimum_should_match": 1
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "source.ip": "172.17.6.6"
              }
            },
            {
              "term": {
                "destination.ip": "172.17.2.3"
              }
            },
            {
              "term": {
                "event.dataset": "zeek.conn"
              }
            }
          ]
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "source.ip": "172.17.6.6"
              }
            },
            {
              "bool": {
                "should": [
                  {
                    "term": {
                      "rule.name": "ET MALWARE Cobalt Strike Activity (POST)"
                    }
                  },
                  {
                    "term": {
                      "rule.uuid": "2035376"
                    }
                  }
                ],
                "minimum_should_match": 1
              }
            }
          ]
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "destination.ip": "192.168.123.170"
              }
            },
            {
              "term": {
                "destination.port": 22
              }
            }
          ],
          "must_not": [
            {
              "term": {
                "source.ip": "192.168.123.0/24"
              }
            }
          ]
        }
      },
      {
        "bool": {
          "should": [
            {
              "bool": {
                "filter": [
                  {
                    "wildcard": {
                      "file.path": "*\\\\admin$\\\\system32\\\\*"
                    }
                  },
                  {
                    "bool": {
                      "should": [
                        {
                          "terms": {
                            "file.name": [
                              "AdobeARM.exe",
                              "adobearm.exe",
                              "wer.exe"
                            ]
                          }
                        },
                        {
                          "term": {
                            "event.action": "file-create"
                          }
                        }
                      ],
                      "minimum_should_match": 1
                    }
                  }
                ]
              }
            },
            {
              "bool": {
                "filter": [
                  {
                    "term": {
                      "process.name": "System"
                    }
                  },
                  {
                    "term": {
                      "process.pid": 4
                    }
                  },
                  {
                    "term": {
                      "user.name": "svc_cifs"
                    }
                  }
                ]
              }
            }
          ],
          "minimum_should_match": 1
        }
      },
      {
        "bool": {
          "filter": [
            {
              "bool": {
                "should": [
                  {
                    "term": {
                      "dns.question.name": "casepilot360.com"
                    }
                  },
                  {
                    "terms": {
                      "destination.ip": [
                        "185.214.132.47",
                        "202.84.73.50"
                      ]
                    }
                  }
                ],
                "minimum_should_match": 1
              }
            },
            {
              "term": {
                "destination.port": 80
              }
            }
          ]
        }
      }
    ],
    "minimum_should_match": 1
  }
}
```

---

## Per-technique alerts

### [Site2] Process hollowing: update_svc.exe injects rundll32.exe (exec4)

- **id:** `defense-evasion-process-hollowing-rundll32`
- **Tactic / Technique:** Defense Evasion / Privilege Escalation (T1055.012)
- **Severity / Risk score:** critical / 90
- **Source iocs.py entry:** `defense-evasion-process-hollowing-rundll32`

2026-07-14 22:19:09 local — Elastic Defend Threat Intelligence provider, PID 8580 -> suspended rundll32.exe PID 8896, target memory Unbacked/Data.

```json
{
  "bool": {
    "should": [
      {
        "bool": {
          "filter": [
            {
              "term": {
                "process.Ext.api.name": "SetThreadContext"
              }
            },
            {
              "term": {
                "process.Ext.api.behaviors": "execute_shellcode"
              }
            }
          ]
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "process.name": "update_svc.exe"
              }
            },
            {
              "term": {
                "Target.process.name": "rundll32.exe"
              }
            }
          ]
        }
      }
    ],
    "minimum_should_match": 1
  }
}
```

### [Site2] Process hollowing: usercpl2.exe injects rundll32.exe (file1)

- **id:** `defense-evasion-usercpl2-hollow-rundll32`
- **Tactic / Technique:** Defense Evasion / Privilege Escalation (T1055.012)
- **Severity / Risk score:** critical / 90
- **Source iocs.py entry:** `defense-evasion-usercpl2-hollow-rundll32`

2026-07-14 22:48:16.627 local — identical technique/ECS signature to the exec4/MWUS hollowing; same actor tradecraft reused on a second host.

```json
{
  "bool": {
    "should": [
      {
        "bool": {
          "filter": [
            {
              "term": {
                "process.Ext.api.name": "SetThreadContext"
              }
            },
            {
              "term": {
                "process.Ext.api.behaviors": "execute_shellcode"
              }
            }
          ]
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "process.name": "usercpl2.exe"
              }
            },
            {
              "term": {
                "Target.process.name": "rundll32.exe"
              }
            }
          ]
        }
      }
    ],
    "minimum_should_match": 1
  }
}
```

### [Site2] exec4 external C2 beacon to casepilot360.com (jQuery masquerade)

- **id:** `c2-beacon-exec4-jquery`
- **Tactic / Technique:** Command and Control (T1071.001)
- **Severity / Risk score:** critical / 85
- **Source iocs.py entry:** `c2-beacon-exec4-jquery`

2026-07-14 22:59:59 local — Suricata alert, exec4:51060 -> 202.84.73.50:80, Host header casepilot360.com, action allowed (not blocked). exec4 ran this in parallel with the file1 SMB relay.

```json
{
  "bool": {
    "filter": [
      {
        "term": {
          "source.ip": "172.17.6.6"
        }
      },
      {
        "bool": {
          "should": [
            {
              "term": {
                "rule.name": "ET MALWARE Cobalt Strike Activity (POST)"
              }
            },
            {
              "term": {
                "rule.uuid": "2035376"
              }
            }
          ],
          "minimum_should_match": 1
        }
      }
    ]
  }
}
```

### SSH pivot from IT-side host into OT HMI subnet

- **id:** `lm-ssh-to-ot-hmi`
- **Tactic / Technique:** Lateral Movement (T1021.004)
- **Severity / Risk score:** critical / 88
- **Source iocs.py entry:** `lm-ssh-to-ot-hmi`

2026-07-08 02:17:39 UTC (~2026-07-07 22:17 local) — source 172.17.3.6 (Linux OpenSSH_10.3p1 client) to HMI OpenSSH_for_Windows_9.8, auth_success true. Separate T10 track, ~6 days before the main hr2/exec4/file1 chain. Any hit here should be treated as near-zero-false-positive if the IT/OT boundary is properly segmented.

```json
{
  "bool": {
    "filter": [
      {
        "term": {
          "destination.ip": "192.168.123.170"
        }
      },
      {
        "term": {
          "destination.port": 22
        }
      }
    ],
    "must_not": [
      {
        "term": {
          "source.ip": "192.168.123.0/24"
        }
      }
    ]
  }
}
```

### [Site2] AdobeARM.exe initial execution on site2-hr2

- **id:** `exec-adobearm-detonation`
- **Tactic / Technique:** Execution (T1204.002)
- **Severity / Risk score:** high / 73
- **Source iocs.py entry:** `exec-adobearm-detonation`

2026-07-14 20:25:03 local — Sysmon Event ID 3, PID 2520, ran from C:\Users\sophia.jones\Downloads\.

```json
{
  "bool": {
    "filter": [
      {
        "term": {
          "process.name": "AdobeARM.exe"
        }
      },
      {
        "term": {
          "user.name": "sophia.jones"
        }
      },
      {
        "bool": {
          "should": [
            {
              "term": {
                "host.name": "site2-hr2"
              }
            },
            {
              "term": {
                "host.ip": "172.17.7.4"
              }
            }
          ],
          "minimum_should_match": 1
        }
      }
    ]
  }
}
```

### [Site2] Unsigned AdobeARM.exe (masquerade signal)

- **id:** `defense-evasion-unsigned-adobearm`
- **Tactic / Technique:** Defense Evasion (T1036.005)
- **Severity / Risk score:** high / 70
- **Source iocs.py entry:** `defense-evasion-unsigned-adobearm`

Host/path-agnostic hunting rule — real Adobe binaries are signed, so this catches renamed/relocated copies of the same payload too.

```json
{
  "bool": {
    "filter": [
      {
        "term": {
          "process.name": "AdobeARM.exe"
        }
      },
      {
        "term": {
          "process.code_signature.exists": false
        }
      }
    ]
  }
}
```

### [Site2] AdobeARM.exe C2 beacon to 202.84.73.50

- **id:** `c2-adobearm-first-callback`
- **Tactic / Technique:** Command and Control (T1071.001)
- **Severity / Risk score:** high / 75
- **Source iocs.py entry:** `c2-adobearm-first-callback`

2026-07-14 20:25:03.436 local — first of a recurring ~43s-interval beacon (Sysmon Event ID 3, PID 2520).

```json
{
  "bool": {
    "filter": [
      {
        "term": {
          "process.name": "AdobeARM.exe"
        }
      },
      {
        "term": {
          "destination.ip": "202.84.73.50"
        }
      },
      {
        "term": {
          "destination.port": 80
        }
      }
    ]
  }
}
```

### [Site2] iexplorerupdate.exe dropped to user Temp

- **id:** `ingress-iexplorerupdate-drop`
- **Tactic / Technique:** Command and Control (T1105)
- **Severity / Risk score:** high / 73
- **Source iocs.py entry:** `ingress-iexplorerupdate-drop`

2026-07-14 20:38:18.500 local — dropped by AdobeARM.exe (PID 2520). 420,864 bytes, entropy ~3.805, same fingerprint reused as update.exe (exec4) and WerCheck2.exe (hr6).

```json
{
  "bool": {
    "should": [
      {
        "term": {
          "file.name": "iexplorerupdate.exe"
        }
      },
      {
        "wildcard": {
          "file.path": "*\\\\sophia.jones\\\\*\\\\Temp\\\\iexplorerupdate.exe"
        }
      }
    ],
    "minimum_should_match": 1
  }
}
```

### [Site2] DCOM lateral movement to site2-exec4

- **id:** `lm-dcom-to-exec4`
- **Tactic / Technique:** Lateral Movement (T1021.003)
- **Severity / Risk score:** high / 78
- **Source iocs.py entry:** `lm-dcom-to-exec4`

2026-07-14 21:11:40 local — signed powershell.exe (PID 6476) wrote update.exe under user.name svc_cifs, not sophia.jones. Same 420,864-byte payload as iexplorerupdate.exe.

```json
{
  "bool": {
    "should": [
      {
        "wildcard": {
          "file.path": "*\\\\Microsoft Works\\\\update.exe"
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "file.name": "update.exe"
              }
            },
            {
              "bool": {
                "should": [
                  {
                    "term": {
                      "host.name": "site2-exec4"
                    }
                  },
                  {
                    "term": {
                      "host.ip": "172.17.6.6"
                    }
                  }
                ],
                "minimum_should_match": 1
              }
            }
          ]
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "process.name": "powershell.exe"
              }
            },
            {
              "term": {
                "user.name": "svc_cifs"
              }
            },
            {
              "bool": {
                "should": [
                  {
                    "term": {
                      "host.name": "site2-exec4"
                    }
                  },
                  {
                    "term": {
                      "host.ip": "172.17.6.6"
                    }
                  }
                ],
                "minimum_should_match": 1
              }
            }
          ]
        }
      }
    ],
    "minimum_should_match": 1
  }
}
```

### [Site2] MWUS service (update_svc.exe) persistence on exec4

- **id:** `persist-mwus-service`
- **Tactic / Technique:** Persistence (T1543.003)
- **Severity / Risk score:** high / 80
- **Source iocs.py entry:** `persist-mwus-service`

2026-07-14 22:20 — Windows service literally named MWUS running update_svc.exe.

```json
{
  "bool": {
    "filter": [
      {
        "bool": {
          "should": [
            {
              "term": {
                "process.name": "update_svc.exe"
              }
            },
            {
              "wildcard": {
                "process.command_line": "*MWUS*"
              }
            }
          ],
          "minimum_should_match": 1
        }
      },
      {
        "bool": {
          "should": [
            {
              "term": {
                "host.name": "site2-exec4"
              }
            },
            {
              "term": {
                "host.ip": "172.17.6.6"
              }
            }
          ],
          "minimum_should_match": 1
        }
      }
    ]
  }
}
```

### [Site2] WerCheck2.exe dropped to System32 on hr6

- **id:** `defense-evasion-wercheck2-drop`
- **Tactic / Technique:** Defense Evasion (T1036.005)
- **Severity / Risk score:** high / 76
- **Source iocs.py entry:** `defense-evasion-wercheck2-drop`

2026-07-14 22:31:16 local — process.name System (PID 4), user.name svc_cifs: classic remote SMB/ADMIN$ write signature. Same 420,864-byte payload family (3rd host).

```json
{
  "bool": {
    "filter": [
      {
        "term": {
          "file.name": "WerCheck2.exe"
        }
      },
      {
        "bool": {
          "should": [
            {
              "term": {
                "host.name": "site2-hr6"
              }
            },
            {
              "term": {
                "host.ip": "172.17.7.8"
              }
            }
          ],
          "minimum_should_match": 1
        }
      }
    ]
  }
}
```

### [Site2] WerCheck2.exe execution and C2 beacon on hr6

- **id:** `exec-wercheck2-schtask`
- **Tactic / Technique:** Execution (T1053.005)
- **Severity / Risk score:** high / 78
- **Source iocs.py entry:** `exec-wercheck2-schtask`

2026-07-14 22:32:15.418 local — Sysmon Event ID 22 DNS query, PID 1628, resolved casepilot360.com to 202.84.73.50.

```json
{
  "bool": {
    "filter": [
      {
        "bool": {
          "should": [
            {
              "term": {
                "process.name": "WerCheck2.exe"
              }
            },
            {
              "wildcard": {
                "process.command_line": "*WerCheck2*"
              }
            }
          ],
          "minimum_should_match": 1
        }
      },
      {
        "bool": {
          "should": [
            {
              "term": {
                "host.name": "site2-hr6"
              }
            },
            {
              "term": {
                "host.ip": "172.17.7.8"
              }
            }
          ],
          "minimum_should_match": 1
        }
      }
    ]
  }
}
```

### [Site2] usercpl2.exe dropped to System32 on file1

- **id:** `defense-evasion-usercpl2-drop`
- **Tactic / Technique:** Defense Evasion (T1036.005)
- **Severity / Risk score:** high / 76
- **Source iocs.py entry:** `defense-evasion-usercpl2-drop`

2026-07-14 22:48:03 local (MSEL said 22:41 — corrected). process.name System / user svc_cifs, 420,864 bytes, MZ header, entropy ~3.805.

```json
{
  "bool": {
    "filter": [
      {
        "term": {
          "file.path": "C:\\\\windows\\\\system32\\\\usercpl2.exe"
        }
      },
      {
        "term": {
          "event.action": "creation"
        }
      },
      {
        "term": {
          "host.name": "site2-file1"
        }
      }
    ]
  }
}
```

### [Site2] usercpl2 (User CPL) service installed on file1

- **id:** `persist-usercpl2-service`
- **Tactic / Technique:** Persistence (T1543.003)
- **Severity / Risk score:** high / 80
- **Source iocs.py entry:** `persist-usercpl2-service`

2026-07-14 22:43:02 local — SCM event 7045, ServiceName 'User CPL', ImagePath usercpl2exe, AccountName LocalSystem. Preceded the file drop by 5 minutes (service stub created first).

```json
{
  "bool": {
    "filter": [
      {
        "term": {
          "event.code": "7045"
        }
      },
      {
        "term": {
          "host.name": "site2-file1"
        }
      }
    ]
  }
}
```

### [Site2] usercpl2.exe service execution on file1

- **id:** `exec-usercpl2-service-start`
- **Tactic / Technique:** Execution (T1569.002)
- **Severity / Risk score:** high / 78
- **Source iocs.py entry:** `exec-usercpl2-service-start`

2026-07-14 22:48:15.542 local (MSEL said 22:47 — corrected; predates the binary's own existence at that time). Parent services.exe, unsigned, SYSTEM integrity. SHA256 31594eb9ca3ab182ee1ab6de7b29e0395926b970c347d61520fc54b89bc56b77.

```json
{
  "bool": {
    "filter": [
      {
        "term": {
          "process.name": "usercpl2.exe"
        }
      },
      {
        "term": {
          "event.category": "process"
        }
      },
      {
        "term": {
          "event.action": "start"
        }
      },
      {
        "term": {
          "host.name": "site2-file1"
        }
      }
    ]
  }
}
```

### [Site2] Anomalous long-lived SMB session exec4 -> file1 (beacon relay)

- **id:** `lm-smb-link-file1`
- **Tactic / Technique:** Lateral Movement (T1021.002)
- **Severity / Risk score:** high / 72
- **Source iocs.py entry:** `lm-smb-link-file1`

2026-07-14 22:48:18 local — 139,148s duration (~38.6h), ~39.7MB/~755k packets, conn_state RSTO. Consider adding a duration/byte-volume range filter (e.g. event.duration > 3600) to isolate the anomaly from ordinary admin-share traffic on this same port/host pair.

```json
{
  "bool": {
    "filter": [
      {
        "term": {
          "source.ip": "172.17.6.6"
        }
      },
      {
        "term": {
          "destination.ip": "172.17.2.3"
        }
      },
      {
        "term": {
          "event.dataset": "zeek.conn"
        }
      }
    ]
  }
}
```

### [Site2] File write to ADMIN$ share via System/svc_cifs (lateral tool transfer)

- **id:** `lm-admin-share-upload`
- **Tactic / Technique:** Lateral Movement (T1021.002)
- **Severity / Risk score:** high / 74
- **Source iocs.py entry:** `lm-admin-share-upload`

Confirmed for hr6 (WerCheck2.exe) — process.name System (PID 4) + user.name svc_cifs is the classic remote-SMB-write fingerprint. Plausible but unconfirmed on exec4/file1.

```json
{
  "bool": {
    "should": [
      {
        "bool": {
          "filter": [
            {
              "wildcard": {
                "file.path": "*\\\\admin$\\\\system32\\\\*"
              }
            },
            {
              "bool": {
                "should": [
                  {
                    "terms": {
                      "file.name": [
                        "AdobeARM.exe",
                        "adobearm.exe",
                        "wer.exe"
                      ]
                    }
                  },
                  {
                    "term": {
                      "event.action": "file-create"
                    }
                  }
                ],
                "minimum_should_match": 1
              }
            }
          ]
        }
      },
      {
        "bool": {
          "filter": [
            {
              "term": {
                "process.name": "System"
              }
            },
            {
              "term": {
                "process.pid": 4
              }
            },
            {
              "term": {
                "user.name": "svc_cifs"
              }
            }
          ]
        }
      }
    ],
    "minimum_should_match": 1
  }
}
```

### [Site2] HTTP beacon to primary redirector casepilot360.com

- **id:** `c2-primary-http-beacon`
- **Tactic / Technique:** Command and Control (T1071.001)
- **Severity / Risk score:** high / 75
- **Source iocs.py entry:** `c2-primary-http-beacon`

casepilot360.com resolves to 202.84.73.50 (confirmed via hr6's Sysmon DNS query); 185.214.132.47 is the original ops-plan IP, kept in case it's still live. Only casepilot360.com of the 4 planned redirectors was actually used.

```json
{
  "bool": {
    "filter": [
      {
        "bool": {
          "should": [
            {
              "term": {
                "dns.question.name": "casepilot360.com"
              }
            },
            {
              "terms": {
                "destination.ip": [
                  "185.214.132.47",
                  "202.84.73.50"
                ]
              }
            }
          ],
          "minimum_should_match": 1
        }
      },
      {
        "term": {
          "destination.port": 80
        }
      }
    ]
  }
}
```

### [Site2] Timestomp of iexplorerupdate.exe (Sysmon FileCreateTime)

- **id:** `defense-evasion-timestomp-iexplorerupdate`
- **Tactic / Technique:** Defense Evasion (T1070.006)
- **Severity / Risk score:** medium / 47
- **Source iocs.py entry:** `defense-evasion-timestomp-iexplorerupdate`

2026-07-14 20:38 local — Sysmon Event ID 2 is rare in normal operation; narrow with process.name/file.name if noisy.

```json
{
  "bool": {
    "filter": [
      {
        "term": {
          "event.code": "2"
        }
      },
      {
        "term": {
          "event.provider": "Microsoft-Windows-Sysmon"
        }
      }
    ]
  }
}
```

### [Site2] Portscan of site2-web sourced from hr6

- **id:** `discovery-webserver-portscan`
- **Tactic / Technique:** Discovery (T1046)
- **Severity / Risk score:** medium / 47
- **Source iocs.py entry:** `discovery-webserver-portscan`

2026-07-14 22:33:30.419 local — Zeek conn.log, ICMP echo request. Source corrected from an earlier exec4 assumption to hr6.

```json
{
  "bool": {
    "filter": [
      {
        "term": {
          "source.ip": "172.17.7.8"
        }
      },
      {
        "term": {
          "destination.ip": "172.17.1.5"
        }
      }
    ]
  }
}
```

### [Site2] SMB enumeration of file1 from exec4

- **id:** `discovery-file1-enum`
- **Tactic / Technique:** Discovery (T1135)
- **Severity / Risk score:** medium / 55
- **Source iocs.py entry:** `discovery-file1-enum`

2026-07-14 22:38 — tool-agnostic network-layer detection (Zeek smb_files.log); catches net view, Get-ChildItem, Get-SmbShare, WMI, Explorer alike.

```json
{
  "bool": {
    "filter": [
      {
        "term": {
          "source.ip": "172.17.6.6"
        }
      },
      {
        "term": {
          "destination.ip": "172.17.2.3"
        }
      },
      {
        "term": {
          "destination.port": 445
        }
      }
    ]
  }
}
```

### [Site2] Recon scan of edge router preceding intrusion

- **id:** `recon-nmap-scan`
- **Tactic / Technique:** Discovery (T1046)
- **Severity / Risk score:** low / 21
- **Source iocs.py entry:** `recon-nmap-scan`

2026-07-13 21:28:42 ET — SSH banner-grab (auth_attempts: 0) against the edge router, confirmed via Zeek ssh.log.

```json
{
  "bool": {
    "filter": [
      {
        "term": {
          "source.ip": "103.195.145.2"
        }
      },
      {
        "term": {
          "destination.ip": "104.53.222.2"
        }
      },
      {
        "term": {
          "destination.port": 22
        }
      }
    ]
  }
}
```

---

## Using these in Kibana

1. Go to **Stack Management > Rules and Connectors > Create rule > Elasticsearch query**.
2. Choose **Query DSL** as the query type and paste the JSON block for the alert you want.
3. Set the index pattern (e.g. `logs-*`), time field `@timestamp`, and a schedule interval (5m is a reasonable default).
4. Set threshold `> 0` matches to alert on any hit.
5. Field-type note: string fields above assume standard ECS keyword mapping (host.name, process.name, file.name, file.path, event.action/category/code/dataset, user.name, rule.name, dns.question.name). If your data stream maps any of these as analyzed text instead, switch `term`/`wildcard` to `<field>.keyword` or `match_phrase` — the same lesson learned repeatedly with KQL field guesses throughout this investigation.
