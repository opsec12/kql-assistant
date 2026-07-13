mkdir -p ~/kql-assistant/templates
cd ~/kql-assistant

cat > app.py << 'PYEOF'
"""
KQL Assistant — local, free natural-language-to-Elasticsearch-KQL tool.

Uses a locally running Ollama model (default: llama3) instead of a paid API.
No data leaves your machine. Generates generic ECS-style Kibana Query
Language (KQL), not schema-bound to any specific cluster.

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

app = Flask(__name__)

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")

SYSTEM_PROMPT = """You are a security detection engineer that translates plain-English \
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
"""

FEWSHOT = [
    {
        "role": "user",
        "content": "find logs with ip 172.17.3.6",
    },
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


def strip_code_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
    text = re.sub(r"\n?```$", "", text)
    return text.strip()


@app.route("/")
def index():
    return render_template("index.html", model=OLLAMA_MODEL)


@app.route("/generate", methods=["POST"])
def generate():
    data = request.get_json(force=True, silent=True) or {}
    user_query = (data.get("query") or "").strip()

    if not user_query:
        return jsonify({"error": "Please describe what you're hunting for."}), 400

    messages = [{"role": "system", "content": SYSTEM_PROMPT}] + FEWSHOT + [
        {"role": "user", "content": user_query}
    ]

    try:
        resp = requests.post(
            f"{OLLAMA_HOST}/api/chat",
            json={
                "model": OLLAMA_MODEL,
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
    except requests.exceptions.RequestException as exc:
        return jsonify({"error": f"Ollama request failed: {exc}"}), 502

    body = resp.json()
    raw = body.get("message", {}).get("content", "")
    kql = strip_code_fences(raw)
