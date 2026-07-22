"""
KQL Assistant — local, free natural-language-to-query tool for two flavors:

  - "elastic"  : Elasticsearch Kibana Query Language (query-bar syntax)
  - "sentinel" : Microsoft Sentinel / Log Analytics Kusto Query Language (KQL)

Uses a locally running Ollama model (default: llama3) instead of a paid API.
No data leaves your machine.

Also serves a deterministic "Full Hunt Package" per flavor (/playbook) built
from known exercise infrastructure/TTPs — see iocs.py (Elastic) and
sentinel_iocs.py (Sentinel/Kusto).

Run:
    pip install -r requirements.txt
    ollama pull llama3          # one-time, if you don't already have a model
    python app.py
    open http://localhost:5000
"""

import os
import re
import json
import requests
from flask import Flask, request, jsonify, render_template
from iocs import DETECTIONS as ELASTIC_DETECTIONS, KNOWN_INFRASTRUCTURE as ELASTIC_INFRA
from sentinel_iocs import DETECTIONS as SENTINEL_DETECTIONS, KNOWN_INFRASTRUCTURE as SENTINEL_INFRA
from es_dsl_alerts import CONFIRMED_ALERTS as DSL_ALERTS, MASTER_ALERT as DSL_MASTER_ALERT

app = Flask(__name__)

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")

# Models we suggest in the UI dropdown even if the user hasn't pulled them yet.
# Any locally-pulled model not in this list still shows up (tagged "installed"),
# and the UI also lets you type an arbitrary model name.
SUGGESTED_MODELS = ["llama3", "llama3.1", "qwen2.5", "qwen2.5-coder", "mistral", "mistral-nemo"]

# ---------------------------------------------------------------------------
# Elastic (Kibana KQL) flavor
# ---------------------------------------------------------------------------

ELASTIC_ENGAGEMENT_CONTEXT = f"""
Known adversary infrastructure for the current exercise (from red team ops plan) — use \
these real values whenever a request refers to "the beacon", "the redirector", "the C2 \
domain", "the OT/HMI host", etc. instead of inventing placeholder values:

C2 domains: {", ".join(ELASTIC_INFRA["c2_domains"])}
C2 public IPs: {", ".join(ELASTIC_INFRA["c2_public_ips"])}
Internal relay/redirector IPs: {", ".join(ELASTIC_INFRA["c2_internal_relay_ips"])}
SMB beacon pipe pattern: {ELASTIC_INFRA["smb_pipe_pattern"]}
Suspicious C2 user-agent: {ELASTIC_INFRA["suspicious_user_agent"]}
C2 URI patterns: {", ".join(ELASTIC_INFRA["c2_uri_patterns"])}
Known lateral movement targets: {", ".join(ELASTIC_INFRA["known_lateral_movement_targets"])}
OT/HMI asset: {ELASTIC_INFRA["known_ot_asset"]["ip"]} (ports of interest: \
{", ".join(str(p) for p in ELASTIC_INFRA["known_ot_asset"]["ports_of_interest"])})
Dropped payload filenames observed: {", ".join(ELASTIC_INFRA["dropped_payload_names"])}
Credential-theft target files: {", ".join(ELASTIC_INFRA["credential_theft_targets"])}
"""

ELASTIC_SYSTEM_PROMPT = """You are a security detection engineer that translates plain-English \
hunting requests into Elasticsearch Kibana Query Language (KQL) — the query-bar syntax, \
NOT Kusto/Sentinel KQL and NOT full Query DSL JSON.

Rules:
- Output ONLY the KQL query. No explanation, no markdown fences, no commentary.
- Use standard Elastic Common Schema (ECS) field names whenever the request implies a \
  concept, for example:
    source.ip, destination.ip, source.port, destination.port
    url.domain, url.full, dns.question.name, http.request.headers.host
    process.name, process.command_line, process.parent.name
    file.path, file.name, file.hash.sha256
    smb.share, smb.tree
    user.name, host.name, host.ip
    event.action, event.category, event.outcome
    network.protocol, network.transport
- KQL syntax reminders:
    field: "value"           exact/text match
    field: value*            wildcard
    field >= 100              range (numeric/date fields, no quotes)
    a and b / a or b / not a  boolean logic (lowercase keywords)
    "exact phrase"            quoted phrase match
    field: (a or b or c)      grouped OR against one field
- If the request mentions multiple distinct indicators (IP, domain, port, hash, share \
  name, etc.), combine them with parentheses and "or"/"and" as logically appropriate — \
  don't just search one and drop the rest.
- If a request is ambiguous about field name, prefer the most common ECS field for that \
  data type and optionally OR in one or two plausible alternates (e.g. destination.ip vs \
  host.ip) rather than guessing a single obscure field.
- Never invent MITRE ATT&CK IDs or add fields not implied by the request.
""" + "\n" + ELASTIC_ENGAGEMENT_CONTEXT

ELASTIC_FEWSHOT = [
    {"role": "user", "content": "find logs with ip 172.17.3.6"},
    {
        "role": "assistant",
        "content": '(source.ip: "172.17.3.6" or destination.ip: "172.17.3.6" or host.ip: "172.17.3.6")',
    },
    {
        "role": "user",
        "content": "beacon to casepilot360.com on port 80, plus internal beacon 101.96.16.200 port 8081",
    },
    {
        "role": "assistant",
        "content": '((url.domain: "casepilot360.com" or dns.question.name: "casepilot360.com" or http.request.headers.host: "casepilot360.com") and destination.port: 80) or (destination.ip: "101.96.16.200" and destination.port: 8081)',
    },
]

# ---------------------------------------------------------------------------
# Sentinel (Kusto KQL) flavor
# ---------------------------------------------------------------------------

SENTINEL_ENGAGEMENT_CONTEXT = f"""
Known adversary infrastructure for the current exercise (from the NorthGrid Cloud Pivot \
ops plan) — use these real values whenever a request refers to "the contractor account", \
"the compromised IPs", "the service principal", "the AWS role", "the target file", etc. \
instead of inventing placeholder values:

Compromised accounts: {", ".join(SENTINEL_INFRA["compromised_accounts"])}
Attacker IPs: {", ".join(SENTINEL_INFRA["attacker_ips"])}
Target service principal: {SENTINEL_INFRA["target_service_principal"]}
Target AWS role ARN: {SENTINEL_INFRA["target_aws_role_arn"]}
Decoy files: {", ".join(SENTINEL_INFRA["decoy_files"])}
Target file (the real objective): {SENTINEL_INFRA["target_file"]}
Internal systems: {", ".join(SENTINEL_INFRA["internal_systems"])}
Relevant Sentinel/Log Analytics tables: {", ".join(SENTINEL_INFRA["relevant_tables"])}
"""

SENTINEL_SYSTEM_PROMPT = """You are a security detection engineer that translates plain-English \
hunting requests into Microsoft Sentinel / Log Analytics Kusto Query Language (KQL) — real \
Kusto pipe syntax against actual Sentinel table schemas, NOT Elasticsearch's Kibana Query \
Language and NOT SQL.

Rules:
- Output ONLY the KQL query. No explanation, no markdown fences, no commentary.
- Use real Kusto pipe syntax: TableName | where ... | project ... | sort by ... etc.
- Use real Sentinel/Log Analytics table and column names appropriate to the request, e.g.:
    SigninLogs (UserPrincipalName, IPAddress, ResultType, ResultDescription, Location,
        RiskLevelDuringSignIn, RiskState, AppDisplayName)
    AADUserRiskEvents, AADRiskyUsers (UserPrincipalName, RiskEventType, RiskLevel)
    AuditLogs (InitiatedBy, TargetResources, ActivityDisplayName)
    AzureActivity (Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, Resource)
    AADServicePrincipalSignInLogs, AADManagedIdentitySignInLogs (ServicePrincipalName,
        AppDisplayName, ResultType, IPAddress)
    AWSCloudTrail (EventName, SourceIpAddress, UserIdentityArn, RequestParameters,
        ResponseElements, ErrorCode)
    AWSS3ServerAccess (Operation, Requester, RequestURI, HTTPStatus)
    AWSGuardDuty, AWSVPCFlow
    SecurityEvent (Computer, Account, EventID, LogonType, IpAddress, FailureReason)
    DeviceProcessEvents (DeviceName, AccountName, FileName, ProcessCommandLine)
    DeviceNetworkEvents (DeviceName, RemoteIP, RemotePort)
- Combine multiple tables with `union isfuzzy=true (Table1 | where ...), (Table2 | where ...)` \
  when a request spans more than one data source (e.g. "everywhere this IP shows up").
- Use `let` statements for reusable values (accounts, IPs, role names) when a query \
  references more than 2-3 literal values, for readability.
- Use has / has_any for substring/token matching, == for exact matches, in ("a","b") for \
  small literal sets.
- If the request implies multiple distinct indicators, combine them logically rather than \
  searching only one and dropping the rest.
- Never invent MITRE ATT&CK IDs or reference tables/fields not implied by the request.
""" + "\n" + SENTINEL_ENGAGEMENT_CONTEXT

SENTINEL_FEWSHOT = [
    {"role": "user", "content": "find all sign-ins from ip 45.9.148.112"},
    {
        "role": "assistant",
        "content": (
            'SigninLogs\n'
            '| where IPAddress == "45.9.148.112"\n'
            '| project TimeGenerated, UserPrincipalName, ResultType, ResultDescription, Location, AppDisplayName\n'
            '| sort by TimeGenerated asc'
        ),
    },
    {"role": "user", "content": "show AssumeRole activity for the NorthGridEngineeringAccess role"},
    {
        "role": "assistant",
        "content": (
            'AWSCloudTrail\n'
            '| where EventName == "AssumeRole"\n'
            '| where RequestParameters has "NorthGridEngineeringAccess" or ResponseElements has "NorthGridEngineeringAccess"\n'
            '| project TimeGenerated, EventName, SourceIpAddress, UserIdentityArn, ErrorCode, ResponseElements\n'
            '| sort by TimeGenerated asc'
        ),
    },
]

FLAVORS = {
    "elastic": {
        "system_prompt": ELASTIC_SYSTEM_PROMPT,
        "fewshot": ELASTIC_FEWSHOT,
        "detections": ELASTIC_DETECTIONS,
        "infrastructure": ELASTIC_INFRA,
    },
    "sentinel": {
        "system_prompt": SENTINEL_SYSTEM_PROMPT,
        "fewshot": SENTINEL_FEWSHOT,
        "detections": SENTINEL_DETECTIONS,
        "infrastructure": SENTINEL_INFRA,
    },
}


def strip_code_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
    text = re.sub(r"\n?```$", "", text)
    return text.strip()


@app.route("/")
def index():
    return render_template(
        "index.html",
        model=OLLAMA_MODEL,
        elastic_count=len(ELASTIC_DETECTIONS),
        sentinel_count=len(SENTINEL_DETECTIONS),
        dsl_count=len(DSL_ALERTS),
    )


@app.route("/models", methods=["GET"])
def models():
    """List installed Ollama models plus a suggested set for the picker."""
    installed = []
    reachable = True
    try:
        resp = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
        resp.raise_for_status()
        for m in resp.json().get("models", []):
            name = m.get("name") or m.get("model") or ""
            # strip the ":latest"/":8b" tag suffix for a cleaner picker label
            base = name.split(":")[0]
            if base and base not in installed:
                installed.append(base)
    except requests.exceptions.RequestException:
        reachable = False

    return jsonify({
        "default": OLLAMA_MODEL,
        "installed": sorted(installed),
        "suggested": SUGGESTED_MODELS,
        "ollama_reachable": reachable,
    })


def _ordered_detections(detections):
    """Sequenced entries first (ascending, by confirmed MSEL/telemetry order),
    then unsequenced entries after in their original list order. Detections
    without a 'sequence' key (e.g. Sentinel, or older Elastic entries) sort
    as unsequenced rather than erroring."""
    indexed = list(enumerate(detections))
    return [
        d for _, d in sorted(
            indexed,
            key=lambda pair: (0, pair[1].get("sequence")) if pair[1].get("sequence") is not None
            else (1, pair[0]),
        )
    ]


@app.route("/playbook", methods=["GET"])
def playbook():
    flavor = request.args.get("flavor", "elastic")
    if flavor not in FLAVORS:
        return jsonify({"error": f"Unknown flavor '{flavor}'. Use 'elastic' or 'sentinel'."}), 400
    f = FLAVORS[flavor]
    return jsonify({
        "flavor": flavor,
        "count": len(f["detections"]),
        "infrastructure": f["infrastructure"],
        "detections": _ordered_detections(f["detections"]),
    })


_APP_DIR = os.path.dirname(os.path.abspath(__file__))
NETWORK_DIAGRAM_PATHS = {
    "elastic": os.path.join(_APP_DIR, "NETWORK_DIAGRAM.md"),
    "sentinel": os.path.join(_APP_DIR, "NORTHGRID_NETWORK_DIAGRAM.md"),
}


@app.route("/network-diagram", methods=["GET"])
def network_diagram():
    """Serve a network diagram markdown file split into its Mermaid diagram
    block (for client-side mermaid.js rendering) and the surrounding
    markdown (legend, table, notes — for client-side marked.js rendering).
    ?flavor=elastic (default, Site2 intrusion) or ?flavor=sentinel
    (NorthGrid Azure-to-AWS cloud pivot)."""
    flavor = request.args.get("flavor", "elastic")
    path = NETWORK_DIAGRAM_PATHS.get(flavor)
    if path is None:
        return jsonify({"error": f"Unknown flavor '{flavor}'. Use 'elastic' or 'sentinel'."}), 400

    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        return jsonify({"error": f"{os.path.basename(path)} not found next to app.py"}), 404

    match = re.search(r"```mermaid\n(.*?)\n```", text, re.DOTALL)
    mermaid = match.group(1) if match else None
    markdown_rest = (text[:match.start()] + text[match.end():]) if match else text

    return jsonify({"flavor": flavor, "mermaid": mermaid, "markdown_rest": markdown_rest})


@app.route("/dsl-alerts", methods=["GET"])
def dsl_alerts():
    """CONFIRMED-only Elasticsearch Query DSL alerts (es_dsl_alerts.py) — no
    LLM involved, this is a static, evidence-backed list, same spirit as
    /playbook but for raw Query DSL instead of KQL strings."""
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts = sorted(DSL_ALERTS, key=lambda a: sev_order.get(a.get("severity"), 9))
    return jsonify({
        "count": len(alerts),
        "master": {
            "id": DSL_MASTER_ALERT["id"],
            "name": DSL_MASTER_ALERT["name"],
            "query": json.dumps(DSL_MASTER_ALERT["query"], indent=2),
        },
        "alerts": [
            {
                "id": a["id"],
                "name": a["name"],
                "tactic": a["tactic"],
                "technique_id": a["technique_id"],
                "severity": a["severity"],
                "risk_score": a["risk_score"],
                "source_ioc_id": a["source_ioc_id"],
                "notes": a["notes"],
                "query": json.dumps(a["query"], indent=2),
            }
            for a in alerts
        ],
    })


@app.route("/generate", methods=["POST"])
def generate():
    data = request.get_json(force=True, silent=True) or {}
    user_query = (data.get("query") or "").strip()
    flavor = data.get("flavor", "elastic")
    model = (data.get("model") or "").strip() or OLLAMA_MODEL

    if flavor not in FLAVORS:
        return jsonify({"error": f"Unknown flavor '{flavor}'. Use 'elastic' or 'sentinel'."}), 400

    if not user_query:
        return jsonify({"error": "Please describe what you're hunting for."}), 400

    f = FLAVORS[flavor]
    messages = [{"role": "system", "content": f["system_prompt"]}] + f["fewshot"] + [
        {"role": "user", "content": user_query}
    ]

    try:
        resp = requests.post(
            f"{OLLAMA_HOST}/api/chat",
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": 0.1},
            },
            timeout=120,
        )
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        return jsonify({
            "error": f"Can't reach Ollama at {OLLAMA_HOST}. Is it running? Try: ollama serve"
        }), 502
    except requests.exceptions.HTTPError:
        return jsonify({
            "error": f"Ollama rejected model '{model}'. Pull it first: ollama pull {model}"
        }), 502
    except requests.exceptions.RequestException as exc:
        return jsonify({"error": f"Ollama request failed: {exc}"}), 502

    body = resp.json()
    raw = body.get("message", {}).get("content", "")
    query_text = strip_code_fences(raw)

    return jsonify({"query": query_text, "flavor": flavor, "model": model})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
