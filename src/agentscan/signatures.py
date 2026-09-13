"""
signatures.py — Fingerprint database for exposed AI / agent services.

Each entry describes a service, one or more read-only HTTP probes used to
identify it, and the curl commands to interact with it once found.

Schema
------
service      : human name
vendor       : vendor / project
category     : 'llm-inference' | 'agent-platform' | 'web-ui' | 'automation' | 'mcp' | 'notebook'
ports        : default TCP ports (used when --ports=auto)
probes       : ordered list of read-only requests.
               { path, method (default GET), body (default None),
                 headers (optional dict),
                 match : list of conditions (ALL must pass)
                 strong: bool   # strong=True counts as confident detection
                 snippet: str   # key to keep as evidence (optional) }
auth_status  : HTTP statuses that mean "authentication is enforced"
login_markers: substrings in body that indicate a login page / auth wall
auth_by_default: True if the product ships with auth ON (so a 200 on a
               data endpoint is the anomaly worth flagging)
severity_noauth: severity to assign when detected unauthenticated
commands     : read-only interaction commands (curl). {url} is substituted
               with the scheme://host:port base. Marked safe interaction only.
notes        : one-line context for the analyst
"""

# Condition helpers ---------------------------------------------------------
# type: status      -> {"type":"status","in":[...]}
# type: contains    -> {"type":"contains","value":"str"}
# type: not_contains-> {"type":"not_contains","value":"str"}
# type: json_key    -> {"type":"json_key","value":"dotted.path"}
# type: json_value  -> {"type":"json_value","value":"dotted.path","equals":...}
# type: header      -> {"type":"header","name":"x","contains":"str"}


def C_STATUS(*codes):
    return {"type": "status", "in": list(codes)}


def C_CONTAINS(v):
    return {"type": "contains", "value": v}


def C_NOT_CONTAINS(v):
    return {"type": "not_contains", "value": v}


def C_JSON_KEY(path):
    return {"type": "json_key", "value": path}


def C_JSON_VALUE(path, equals):
    return {"type": "json_value", "value": path, "equals": equals}


def C_HEADER(name, contains):
    return {"type": "header", "name": name, "contains": contains}


def C_JSON():
    """Body parses as JSON (object or array) — kills SPA/HTML false positives."""
    return {"type": "json"}


SIGNATURES = [

    # ===================== LLM INFERENCE ==================================
    {
        "service": "Ollama",
        "vendor": "Ollama",
        "category": "llm-inference",
        "ports": [11434, 11435],
        "probes": [
            {"path": "/api/tags", "match": [C_STATUS(200), C_JSON_KEY("models")],
             "strong": True, "snippet": "models"},
            {"path": "/api/version", "match": [C_STATUS(200), C_JSON_KEY("version")],
             "strong": True, "snippet": "version"},
            {"path": "/api/ps", "match": [C_STATUS(200), C_JSON_KEY("models")],
             "strong": False, "snippet": "models"},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": False,
        "severity_noauth": "high",
        "commands": [
            ("List installed models", "curl -s {url}/api/tags"),
            ("Server version", "curl -s {url}/api/version"),
            ("Running models", "curl -s {url}/api/ps"),
            ("Show model details (READ-ONLY)",
             "curl -s {url}/api/show -d '{\"name\":\"<model>\"}'"),
            ("Model info (OpenAI-compatible)", "curl -s {url}/v1/models"),
        ],
        "notes": "Ollama ships with NO authentication. Exposed = full model control + inference.",
    },
    {
        "service": "vLLM (OpenAI-compatible)",
        "vendor": "vLLM",
        "category": "llm-inference",
        "ports": [8000, 8001, 8080, 9100, 9000],
        "probes": [
            {"path": "/v1/models", "match": [C_STATUS(200), C_JSON_VALUE("object", "list"),
                                              C_JSON_KEY("data")],
             "strong": True, "snippet": "data"},
            {"path": "/version", "match": [C_STATUS(200), C_JSON_KEY("version")],
             "strong": True, "snippet": "version"},
            {"path": "/health", "match": [C_STATUS(200)],
             "strong": False, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": False,
        "severity_noauth": "high",
        "commands": [
            ("List served models", "curl -s {url}/v1/models"),
            ("Version", "curl -s {url}/version"),
            ("Health", "curl -s {url}/health"),
            ("Server metrics (may leak prompts)", "curl -s {url}/metrics"),
        ],
        "notes": "vLLM's /v1/models is unauthenticated unless --api-key is configured.",
    },
    {
        "service": "localai",
        "vendor": "LocalAI",
        "category": "llm-inference",
        "ports": [8080],
        "probes": [
            {"path": "/v1/models", "match": [C_STATUS(200), C_JSON_KEY("data")],
             "strong": True, "snippet": "data"},
            {"path": "/readyz", "match": [C_STATUS(200)],
             "strong": False, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": False,
        "severity_noauth": "high",
        "commands": [
            ("List models", "curl -s {url}/v1/models"),
            ("Readiness", "curl -s {url}/readyz"),
        ],
        "notes": "LocalAI API is unauthenticated by default.",
    },
    {
        "service": "LiteLLM proxy",
        "vendor": "BerriAI",
        "category": "llm-inference",
        "ports": [4000, 8000],
        "probes": [
            {"path": "/v1/models", "match": [C_STATUS(200), C_JSON_KEY("data")],
             "strong": True, "snippet": "data"},
            {"path": "/health/readiness", "match": [C_STATUS(200), C_JSON_KEY("status")],
             "strong": True, "snippet": "status"},
            {"path": "/health", "match": [C_STATUS(200)], "strong": False, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": True,
        "severity_noauth": "high",
        "commands": [
            ("List models (may expose upstream keys)", "curl -s {url}/v1/models"),
            ("Readiness", "curl -s {url}/health/readiness"),
            ("Model info", "curl -s {url}/model/info"),
        ],
        "notes": "LiteLLM brokers many upstream providers — unauth access can leak API keys & spend budget.",
    },
    {
        "service": "llama.cpp server",
        "vendor": "ggerganov/llama.cpp",
        "category": "llm-inference",
        "ports": [8080, 8000],
        "probes": [
            {"path": "/health", "match": [C_STATUS(200), C_JSON_VALUE("status", "ok")],
             "strong": True, "snippet": "status"},
            {"path": "/props", "match": [C_STATUS(200), C_JSON_KEY("default_generation_settings")],
             "strong": True, "snippet": None},
            {"path": "/v1/models", "match": [C_STATUS(200), C_JSON_KEY("data")],
             "strong": True, "snippet": "data"},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": False,
        "severity_noauth": "high",
        "commands": [
            ("Health", "curl -s {url}/health"),
            ("Server props / model path", "curl -s {url}/props"),
            ("List models", "curl -s {url}/v1/models"),
        ],
        "notes": "llama-server has no built-in auth; /props can leak filesystem paths.",
    },
    {
        "service": "Text Generation WebUI (oobabooga)",
        "vendor": "oobabooga",
        "category": "llm-inference",
        "ports": [5000, 7860, 5001],
        "probes": [
            {"path": "/api/v1/model", "match": [C_STATUS(200), C_JSON_KEY("result")],
             "strong": True, "snippet": "result"},
            {"path": "/api/v1/internal/model_info", "match": [C_STATUS(200)],
             "strong": False, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": ["login", "credentials"],
        "auth_by_default": False,
        "severity_noauth": "high",
        "commands": [
            ("Current model", "curl -s {url}/api/v1/model"),
            ("Model list", "curl -s {url}/v1/internal/model/list"),
            ("Load state", "curl -s {url}/api/v1/internal/load-logs"),
        ],
        "notes": "The --api flag exposes an unauthenticated control API (model load/unload).",
    },
    {
        "service": "KoboldCpp",
        "vendor": "LostRuins",
        "category": "llm-inference",
        "ports": [5001, 5000],
        "probes": [
            {"path": "/api/v1/model", "match": [C_STATUS(200), C_JSON_KEY("result")],
             "strong": True, "snippet": "result"},
            {"path": "/api/extra/version", "match": [C_STATUS(200), C_JSON_KEY("result")],
             "strong": True, "snippet": "result"},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": False,
        "severity_noauth": "high",
        "commands": [
            ("Model", "curl -s {url}/api/v1/model"),
            ("Version", "curl -s {url}/api/extra/version"),
            ("True max context", "curl -s {url}/api/extra/truemaxctx"),
        ],
        "notes": "KoboldCpp API is unauthenticated by default.",
    },
    {
        "service": "TabbyAPI",
        "vendor": "theroyallab",
        "category": "llm-inference",
        "ports": [5000, 8000],
        "probes": [
            {"path": "/v1/models", "match": [C_STATUS(200), C_JSON_KEY("data")],
             "strong": True, "snippet": "data"},
            {"path": "/v1/model", "match": [C_STATUS(200), C_JSON_KEY("id")],
             "strong": True, "snippet": "id"},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": False,
        "severity_noauth": "medium",
        "commands": [
            ("List models", "curl -s {url}/v1/models"),
            ("Loaded model", "curl -s {url}/v1/model"),
        ],
        "notes": "TabbyAPI is unauthenticated unless api_key is set in config.",
    },
    {
        "service": "Aphrodite Engine",
        "vendor": "PygmalionAI",
        "category": "llm-inference",
        "ports": [2242],
        "probes": [
            {"path": "/v1/models", "match": [C_STATUS(200), C_JSON_KEY("data")],
             "strong": True, "snippet": "data"},
            {"path": "/health", "match": [C_STATUS(200)], "strong": False, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": False,
        "severity_noauth": "medium",
        "commands": [
            ("List models", "curl -s {url}/v1/models"),
            ("Health", "curl -s {url}/health"),
        ],
        "notes": "Aphrodite is OpenAI-compatible, unauthenticated by default.",
    },
    {
        "service": "HuggingFace TGI",
        "vendor": "HuggingFace",
        "category": "llm-inference",
        "ports": [80, 8080, 8000],
        "probes": [
            {"path": "/info", "match": [C_STATUS(200), C_JSON_KEY("model_id")],
             "strong": True, "snippet": "model_id"},
            {"path": "/health", "match": [C_STATUS(200)], "strong": False, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": False,
        "severity_noauth": "medium",
        "commands": [
            ("Model info", "curl -s {url}/info"),
            ("Health", "curl -s {url}/health"),
        ],
        "notes": "TGI /info is unauthenticated unless a token gateway is in front.",
    },
    {
        "service": "Xinference",
        "vendor": "Xorbits",
        "category": "llm-inference",
        "ports": [9997],
        "probes": [
            {"path": "/v1/models", "match": [C_STATUS(200), C_JSON_KEY("data")],
             "strong": True, "snippet": "data"},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": False,
        "severity_noauth": "high",
        "commands": [
            ("List models", "curl -s {url}/v1/models"),
            ("Running models", "curl -s {url}/v1/cluster/models"),
        ],
        "notes": "Xinference default deployment is unauthenticated; model management is exposed.",
    },
    {
        "service": "LM Studio server",
        "vendor": "LM Studio",
        "category": "llm-inference",
        "ports": [1234],
        "probes": [
            {"path": "/v1/models", "match": [C_STATUS(200), C_JSON_KEY("data")],
             "strong": True, "snippet": "data"},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": False,
        "severity_noauth": "high",
        "commands": [
            ("List models", "curl -s {url}/v1/models"),
        ],
        "notes": "LM Studio server (localhost by default) exposes OpenAI API without auth.",
    },

    # ===================== AGENT PLATFORMS / AUTOMATION ===================
    {
        "service": "Flowise",
        "vendor": "FlowiseAI",
        "category": "agent-platform",
        "ports": [3000, 3001],
        "probes": [
            {"path": "/api/v1/version", "match": [C_STATUS(200), C_JSON_KEY("version")],
             "strong": True, "snippet": "version"},
            {"path": "/api/v1/public-chatflows", "match": [C_STATUS(200), C_JSON()],
             "strong": True, "snippet": None},
            {"path": "/api/v1/chatflows", "match": [C_STATUS(200), C_JSON()],
             "strong": True, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": ["/signin", "Flowise", "login"],
        "auth_by_default": True,
        "severity_noauth": "high",
        "commands": [
            ("Version", "curl -s {url}/api/v1/version"),
            ("List chatflows (flows + tool configs)", "curl -s {url}/api/v1/chatflows"),
            ("List assisted targets", "curl -s {url}/api/v1/tools"),
            ("List credentials metadata", "curl -s {url}/api/v1/credentials"),
        ],
        "notes": "Flowise <2.0 had no auth by default; unauth chatflows leak prompts, API keys, and RCE-capable custom tools.",
    },
    {
        "service": "Langflow",
        "vendor": "Langflow / DataStax",
        "category": "agent-platform",
        "ports": [7860, 3000],
        "probes": [
            {"path": "/health", "match": [C_STATUS(200)], "strong": False, "snippet": None},
            {"path": "/api/v1/version", "match": [C_STATUS(200), C_JSON_KEY("version")],
             "strong": True, "snippet": "version"},
            {"path": "/api/v1/flows/", "match": [C_STATUS(200), C_JSON()], "strong": True, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": ["login", "Langflow"],
        "auth_by_default": True,
        "severity_noauth": "high",
        "commands": [
            ("Version", "curl -s {url}/api/v1/version"),
            ("List flows", "curl -s {url}/api/v1/flows/"),
            ("Auto-login config", "curl -s {url}/api/v1/auto_login"),
        ],
        "notes": "Langflow with AUTO_LOGIN=true or missing auth exposes flow definitions and code execution nodes.",
    },
    {
        "service": "n8n automation",
        "vendor": "n8n",
        "category": "automation",
        "ports": [5678],
        "probes": [
            {"path": "/rest/settings", "match": [C_STATUS(200), C_JSON_KEY("data")],
             "strong": True, "snippet": "data"},
            {"path": "/healthz", "match": [C_STATUS(200)], "strong": False, "snippet": None},
            {"path": "/rest/workflows", "match": [C_STATUS(200), C_JSON()], "strong": True, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": ["/signin", "n8n"],
        "auth_by_default": True,
        "severity_noauth": "high",
        "commands": [
            ("Settings / feature flags", "curl -s {url}/rest/settings"),
            ("List workflows (if unauth)", "curl -s {url}/rest/workflows"),
            ("List credentials metadata", "curl -s {url}/rest/credentials"),
        ],
        "notes": "Exposed /rest/workflows without auth = full read of automations & stored credential names.",
    },
    {
        "service": "Dify",
        "vendor": "LangGenius",
        "category": "agent-platform",
        "ports": [80, 3000, 8080],
        "probes": [
            {"path": "/console/api/setup", "match": [C_STATUS(200), C_JSON_KEY("step")],
             "strong": True, "snippet": "step"},
            {"path": "/health", "match": [C_STATUS(200)], "strong": False, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": ["signin", "Dify"],
        "auth_by_default": True,
        "severity_noauth": "medium",
        "commands": [
            ("Setup status (reveals if init done)", "curl -s {url}/console/api/setup"),
            ("Health", "curl -s {url}/health"),
        ],
        "notes": "/console/api/setup is unauthenticated by design; 'finished' confirms a ready, configured instance.",
    },
    {
        "service": "AnythingLLM",
        "vendor": "Mintplex Labs",
        "category": "agent-platform",
        "ports": [3001],
        "probes": [
            {"path": "/api/ping", "match": [C_STATUS(200)], "strong": False, "snippet": None},
            {"path": "/api/system/system-vectors", "match": [C_STATUS(200), C_JSON()], "strong": True, "snippet": None},
            {"path": "/api/v1/admin/workspaces", "match": [C_STATUS(200), C_JSON()], "strong": True, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": ["login", "AnythingLLM"],
        "auth_by_default": True,
        "severity_noauth": "high",
        "commands": [
            ("Ping", "curl -s {url}/api/ping"),
            ("System vector config", "curl -s {url}/api/system/system-vectors"),
            ("List workspaces (if unauth)", "curl -s {url}/api/v1/admin/workspaces"),
        ],
        "notes": "Password gate exists but is bypassable via the local API if exposed; admin endpoints leak workspaces and keys.",
    },
    {
        "service": "AutoGPT / agent REST",
        "vendor": "Significant Gravitas",
        "category": "agent-platform",
        "ports": [8000, 3000],
        "probes": [
            {"path": "/api/v1/agent", "match": [C_STATUS(200)], "strong": False, "snippet": None},
            {"path": "/docs", "match": [C_STATUS(200), C_CONTAINS("swagger")],
             "strong": False, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": ["login"],
        "auth_by_default": False,
        "severity_noauth": "medium",
        "commands": [
            ("API docs", "curl -s {url}/docs"),
            ("OpenAPI schema", "curl -s {url}/openapi.json"),
        ],
        "notes": "Generic agent REST services (FastAPI) frequently expose /docs and /openapi.json unauthenticated.",
    },

    # ===================== WEB UIs ========================================
    {
        "service": "Open WebUI",
        "vendor": "open-webui",
        "category": "web-ui",
        "ports": [8080, 3000],
        "probes": [
            {"path": "/api/config", "match": [C_STATUS(200), C_JSON_KEY("features")],
             "strong": True, "snippet": None},
            {"path": "/api/version", "match": [C_STATUS(200), C_JSON()], "strong": True, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": ["login", "Open WebUI"],
        "auth_by_default": True,
        "severity_noauth": "medium",
        "commands": [
            ("Public config / feature flags", "curl -s {url}/api/config"),
            ("Version", "curl -s {url}/api/version"),
        ],
        "notes": "/api/config is intentionally public but discloses enabled features and OAuth settings.",
    },
    {
        "service": "Gradio app",
        "vendor": "Gradio",
        "category": "web-ui",
        "ports": [7860, 7861, 8501],
        "probes": [
            {"path": "/config", "match": [C_STATUS(200), C_JSON_KEY("version"),
                                           C_JSON_KEY("components")],
             "strong": True, "snippet": "version"},
            {"path": "/info", "match": [C_STATUS(200), C_JSON_KEY("named_endpoints")],
             "strong": True, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": ["login", "auth"],
        "auth_by_default": False,
        "severity_noauth": "high",
        "commands": [
            ("App config (API names, components)", "curl -s {url}/config"),
            ("Endpoint map", "curl -s {url}/info"),
        ],
        "notes": "Gradio /config and /info expose every API endpoint and are unauthenticated unless auth=... is set.",
    },
    {
        "service": "Streamlit app",
        "vendor": "Streamlit",
        "category": "web-ui",
        "ports": [8501, 8502],
        "probes": [
            {"path": "/_stcore/health", "match": [C_STATUS(200), C_CONTAINS("ok")],
             "strong": True, "snippet": None},
            {"path": "/healthz", "match": [C_STATUS(200)], "strong": False, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": ["login"],
        "auth_by_default": False,
        "severity_noauth": "medium",
        "commands": [
            ("Health", "curl -s {url}/_stcore/health"),
        ],
        "notes": "Streamlit has no built-in auth; any exposed app is fully usable by anyone.",
    },
    {
        "service": "ComfyUI",
        "vendor": "comfyanonymous",
        "category": "web-ui",
        "ports": [8188, 8189],
        "probes": [
            {"path": "/system_stats", "match": [C_STATUS(200), C_JSON_KEY("system"),
                                                 C_JSON_KEY("devices")],
             "strong": True, "snippet": "system"},
            {"path": "/object_info", "match": [C_STATUS(200), C_JSON()], "strong": False, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": False,
        "severity_noauth": "high",
        "commands": [
            ("System stats (host/GPU/VRAM)", "curl -s {url}/system_stats"),
            ("Queue state", "curl -s {url}/queue"),
            ("Node object info", "curl -s {url}/object_info"),
            ("Model folders", "curl -s {url}/models"),
        ],
        "notes": "ComfyUI listens on 0.0.0.0 with no auth and exposes filesystem-backed model paths and queue control.",
    },

    # ===================== MCP ============================================
    {
        "service": "MCP server (SSE / HTTP)",
        "vendor": "Model Context Protocol",
        "category": "mcp",
        "ports": [8000, 3000, 8080, 9000],
        "probes": [
            {"path": "/sse", "match": [C_STATUS(200),
                                       C_HEADER("content-type", "text/event-stream")],
             "strong": True, "snippet": None},
            {"path": "/mcp", "match": [C_STATUS(200, 400, 405, 406)], "strong": False, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": False,
        "severity_noauth": "high",
        "commands": [
            ("SSE event stream (lists tools/resources)",
             "curl -s -N {url}/sse"),
            ("MCP JSON-RPC initialize (READ-ONLY handshake)",
             "curl -s {url}/mcp -H 'Content-Type: application/json' "
             "-d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
             "\"params\":{\"protocolVersion\":\"2024-11-05\","
             "\"capabilities\":{},\"clientInfo\":{\"name\":\"agentscan\",\"version\":\"1.0\"}}}'"),
        ],
        "notes": "Unhandshaked MCP servers leak the full tool list; POSTing is a handshake only — keep it read-only.",
    },

    # ===================== NOTEBOOK / DEV ================================
    {
        "service": "Jupyter Notebook",
        "vendor": "Project Jupyter",
        "category": "notebook",
        "ports": [8888, 8889],
        "probes": [
            {"path": "/api", "match": [C_STATUS(200), C_JSON_KEY("version")],
             "strong": True, "snippet": "version"},
            {"path": "/lab", "match": [C_STATUS(200), C_CONTAINS("jupyter")],
             "strong": False, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": ["login", "token"],
        "auth_by_default": True,
        "severity_noauth": "critical",
        "commands": [
            ("Server version + kernel spec", "curl -s {url}/api"),
            ("List running sessions", "curl -s {url}/api/sessions"),
            ("List notebooks", "curl -s {url}/api/contents"),
        ],
        "notes": "Jupyter without token = interactive code execution (websocket terminal/kernel). Treat as RCE.",
    },

    # ===================== ADDITIONAL AGENT FRAMEWORKS ====================
    {
        "service": "LangServe",
        "vendor": "LangChain",
        "category": "agent-platform",
        "ports": [8000, 8001, 8080],
        "probes": [
            {"path": "/openapi.json",
             "match": [C_STATUS(200), C_CONTAINS("/invoke")],
             "strong": True, "snippet": None},
            {"path": "/playground",
             "match": [C_STATUS(200), C_CONTAINS("LangServe")],
             "strong": True, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": False,
        "severity_noauth": "high",
        "commands": [
            ("OpenAPI schema (lists every chain route)", "curl -s {url}/openapi.json"),
            ("Input schema for the root chain", "curl -s {url}/input_schema"),
            ("Output schema for the root chain", "curl -s {url}/output_schema"),
            ("Config schema", "curl -s {url}/config_schema"),
            ("Interactive playground", "curl -s {url}/playground"),
        ],
        "notes": "LangServe exposes /invoke, /batch and /stream for every deployed chain — unauth reach into tools and LLM provider keys.",
    },
    {
        "service": "Haystack / hayhooks",
        "vendor": "deepset",
        "category": "agent-platform",
        "ports": [1416, 8000],
        "probes": [
            {"path": "/openapi.json",
             "match": [C_STATUS(200), C_CONTAINS("hayhooks")],
             "strong": True, "snippet": None},
            {"path": "/openapi.json",
             "match": [C_STATUS(200), C_CONTAINS("Haystack")],
             "strong": True, "snippet": None},
            {"path": "/status",
             "match": [C_STATUS(200), C_JSON_KEY("status")],
             "strong": False, "snippet": "status"},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": False,
        "severity_noauth": "high",
        "commands": [
            ("Status", "curl -s {url}/status"),
            ("OpenAPI schema (deployed pipelines + routes)", "curl -s {url}/openapi.json"),
            ("List deployed pipelines", "curl -s {url}/pipelines"),
        ],
        "notes": "hayhooks wraps Haystack pipelines as REST APIs; unauth access executes the pipeline (LLM spend, RAG data exposure).",
    },
    {
        "service": "OpenLLM",
        "vendor": "BentoML",
        "category": "llm-inference",
        "ports": [3000, 8000, 8080],
        "probes": [
            {"path": "/openapi.json",
             "match": [C_STATUS(200), C_CONTAINS("OpenLLM")],
             "strong": True, "snippet": None},
            {"path": "/metrics",
             "match": [C_STATUS(200), C_CONTAINS("bentoml")],
             "strong": True, "snippet": None},
            {"path": "/v1/models",
             "match": [C_STATUS(200), C_JSON_KEY("data")],
             "strong": False, "snippet": "data"},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": True,
        "severity_noauth": "high",
        "commands": [
            ("List models", "curl -s {url}/v1/models"),
            ("Readiness", "curl -s {url}/readyz"),
            ("OpenAPI schema", "curl -s {url}/openapi.json"),
            ("Metrics (may leak request paths)", "curl -s {url}/metrics"),
        ],
        "notes": "OpenLLM (BentoML) servers expose /v1/* and /readyz; API auth is optional and disabled in many deployments.",
    },
    {
        "service": "SuperAGI",
        "vendor": "TransformerOptimus",
        "category": "agent-platform",
        "ports": [3000],
        "probes": [
            {"path": "/",
             "match": [C_STATUS(200), C_CONTAINS("SuperAGI")],
             "strong": True, "snippet": None},
            {"path": "/api/",
             "match": [C_STATUS(200), C_JSON()], "strong": False, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": ["login", "signin"],
        "auth_by_default": True,
        "severity_noauth": "high",
        "commands": [
            ("Landing page / version", "curl -s {url}/"),
            ("Swagger (if enabled)", "curl -s {url}/api/docs"),
        ],
        "notes": "An exposed SuperAGI console lets anyone create agents that run tools and spend your LLM API keys.",
    },
    {
        "service": "Chainlit app",
        "vendor": "Chainlit",
        "category": "web-ui",
        "ports": [8000, 8080],
        "probes": [
            {"path": "/project/settings",
             "match": [C_STATUS(200), C_JSON_KEY("ui")],
             "strong": True, "snippet": None},
            {"path": "/",
             "match": [C_STATUS(200), C_CONTAINS("Chainlit")],
             "strong": False, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": ["login"],
        "auth_by_default": False,
        "severity_noauth": "medium",
        "commands": [
            ("Project settings (features, auth mode)", "curl -s {url}/project/settings"),
            ("Landing page", "curl -s {url}/"),
        ],
        "notes": "Chainlit chat UIs are unauthenticated unless auth is explicitly configured.",
    },
    {
        "service": "Letta / MemGPT",
        "vendor": "Letta",
        "category": "agent-platform",
        "ports": [8283, 8000],
        "probes": [
            {"path": "/v1/health/",
             "match": [C_STATUS(200), C_JSON_KEY("version")],
             "strong": True, "snippet": "version"},
            {"path": "/v1/health",
             "match": [C_STATUS(200), C_JSON_KEY("version")],
             "strong": True, "snippet": "version"},
            {"path": "/v1/agents/",
             "match": [C_STATUS(200), C_JSON()], "strong": True, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": [],
        "auth_by_default": True,
        "severity_noauth": "high",
        "commands": [
            ("Health / version", "curl -s {url}/v1/health/"),
            ("List agents (if unauth)", "curl -s {url}/v1/agents/"),
        ],
        "notes": "The Letta agent server stores long-term memory and tool config; unauth access leaks agents and allows message injection.",
    },
    {
        "service": "AutoGen Studio",
        "vendor": "Microsoft",
        "category": "agent-platform",
        "ports": [8081],
        "probes": [
            {"path": "/",
             "match": [C_STATUS(200), C_CONTAINS("AutoGen")],
             "strong": True, "snippet": None},
        ],
        "auth_status": [401, 403],
        "login_markers": ["login"],
        "auth_by_default": False,
        "severity_noauth": "high",
        "commands": [
            ("Landing page", "curl -s {url}/"),
            ("API docs", "curl -s {url}/docs"),
        ],
        "notes": "AutoGen Studio has no built-in authentication; exposed instances let anyone run multi-agent teams.",
    },
]

# ---------------------------------------------------------------------------
# ENDPOINT CATALOG — read-only GET paths to enumerate per detected service.
# Only GET is ever issued; POST-only routes surface as HTTP 405 ("exists").
# OpenAPI (/openapi.json) is parsed automatically for every detected service,
# so frameworks expose their full route list without an entry here.
# ---------------------------------------------------------------------------
ENDPOINT_CATALOG = {
    "Ollama": [
        ("/api/tags", "list local models"), ("/api/version", "server version"),
        ("/api/ps", "running models"), ("/api/show", "model details"),
        ("/api/status", "cloud/account status"),
        ("/api/generate", "text generation"), ("/api/chat", "chat completion"),
        ("/api/embed", "embeddings"), ("/api/embeddings", "legacy embeddings"),
        ("/api/create", "create model"), ("/api/pull", "pull model"),
        ("/api/push", "push model"), ("/api/copy", "copy model"),
        ("/api/delete", "delete model"), ("/api/me", "account info"),
        ("/v1/models", "OpenAI-compatible models"),
        ("/v1/chat/completions", "OpenAI chat completions"),
        ("/v1/completions", "OpenAI completions"),
        ("/v1/embeddings", "OpenAI embeddings"),
        ("/v1/audio/transcriptions", "OpenAI audio transcriptions"),
        ("/v1/images/generations", "OpenAI image generations"),
    ],
    "vLLM (OpenAI-compatible)": [
        ("/v1/models", "served models"), ("/v1/chat/completions", "chat completions"),
        ("/v1/completions", "completions"), ("/v1/embeddings", "embeddings"),
        ("/version", "server version"), ("/health", "health"),
        ("/metrics", "prometheus metrics"),
    ],
    "localai": [
        ("/v1/models", "models"), ("/readyz", "readiness"), ("/metrics", "metrics"),
        ("/version", "version"), ("/v1/chat/completions", "chat completions"),
        ("/v1/embeddings", "embeddings"),
    ],
    "LiteLLM proxy": [
        ("/v1/models", "models"), ("/health/readiness", "readiness"),
        ("/health", "health"), ("/health/liveliness", "liveness"),
        ("/model/info", "model info"), ("/models", "model list"),
        ("/metrics", "metrics"), ("/get/config/callbacks", "callbacks"),
    ],
    "llama.cpp server": [
        ("/health", "health"), ("/props", "server props"), ("/v1/models", "models"),
        ("/v1/chat/completions", "chat completions"), ("/slots", "slots"),
        ("/metrics", "metrics"),
    ],
    "Text Generation WebUI (oobabooga)": [
        ("/api/v1/model", "current model"), ("/v1/internal/model/list", "model list"),
        ("/api/v1/internal/load-logs", "load logs"),
        ("/api/v1/internal/model_info", "model info"),
        ("/v1/internal/model/info", "internal model info"),
        ("/api/v1/stop", "stop server"),
    ],
    "KoboldCpp": [
        ("/api/v1/model", "model"), ("/api/extra/version", "version"),
        ("/api/extra/truemaxctx", "true max context"),
        ("/api/extra/perf", "performance"),
        ("/api/extra/generate/check", "generation check"),
        ("/api/v1/config/max_context_length", "max context length"),
        ("/api/v1/config/max_length", "max length"),
        ("/api/extra/stop", "stop generation"),
    ],
    "TabbyAPI": [
        ("/v1/models", "models"), ("/v1/model", "loaded model"),
        ("/health", "health"), ("/metrics", "metrics"),
    ],
    "Aphrodite Engine": [
        ("/v1/models", "models"), ("/v1/chat/completions", "chat completions"),
        ("/health", "health"), ("/metrics", "metrics"),
    ],
    "HuggingFace TGI": [
        ("/info", "model info"), ("/health", "health"), ("/metrics", "metrics"),
    ],
    "Xinference": [
        ("/v1/models", "models"), ("/v1/cluster/models", "running models"),
        ("/v1/cluster/version", "version"), ("/metrics", "metrics"),
    ],
    "LM Studio server": [
        ("/v1/models", "models"), ("/v1/chat/completions", "chat completions"),
        ("/v1/embeddings", "embeddings"),
    ],
    "Flowise": [
        ("/api/v1/version", "version"), ("/api/v1/chatflows", "chatflows"),
        ("/api/v1/public-chatflows", "public chatflows"), ("/api/v1/tools", "tools"),
        ("/api/v1/credentials", "credentials metadata"),
        ("/api/v1/variables", "variables"), ("/api/v1/nodes", "node catalog"),
        ("/api/v1/assistants", "assistants"), ("/api/v1/leads", "leads"),
        ("/api/v1/ping", "ping"),
    ],
    "Langflow": [
        ("/api/v1/version", "version"), ("/api/v1/flows/", "flows"),
        ("/api/v1/auto_login", "auto-login config"), ("/api/v1/config", "config"),
        ("/api/v1/users/whoami", "current user"), ("/health", "health"),
        ("/api/v1/store/check/", "store check"),
    ],
    "n8n automation": [
        ("/rest/settings", "settings"), ("/rest/login", "login"),
        ("/rest/workflows", "workflows"), ("/rest/credentials", "credentials metadata"),
        ("/rest/credential-types", "credential types"), ("/rest/node-types", "node types"),
        ("/rest/tags", "tags"), ("/rest/active-workflows", "active workflows"),
        ("/rest/executions", "executions"),
        ("/rest/community-node-types", "community nodes"), ("/rest/me", "current user"),
        ("/healthz", "health"), ("/metrics", "metrics"),
    ],
    "Dify": [
        ("/console/api/setup", "setup status"), ("/console/api/version", "version"),
        ("/health", "health"), ("/api/", "API root"),
    ],
    "AnythingLLM": [
        ("/api/ping", "ping"), ("/api/system/system-vectors", "vector config"),
        ("/api/v1/admin/workspaces", "workspaces"), ("/api/workspaces", "workspaces"),
        ("/api/documents", "documents"), ("/api/system/settings", "settings"),
        ("/api/setup-complete", "setup complete"),
    ],
    "Open WebUI": [
        ("/api/config", "public config"), ("/api/version", "version"),
        ("/api/models", "models"), ("/api/tags", "tags"),
        ("/ollama/api/tags", "proxied ollama tags"), ("/api/v1/models", "v1 models"),
    ],
    "Gradio app": [
        ("/config", "app config"), ("/info", "endpoint map"),
        ("/queue/status", "queue status"),
    ],
    "Streamlit app": [("/_stcore/health", "health")],
    "ComfyUI": [
        ("/system_stats", "system stats"), ("/queue", "queue"),
        ("/object_info", "node info"), ("/models", "model folders"),
        ("/history", "execution history"), ("/embeddings", "embeddings list"),
        ("/extensions", "extensions"), ("/features", "features"),
        ("/settings", "settings"), ("/prompt", "prompt queue"),
        ("/internal/logs", "internal logs"), ("/internal/logs/raw", "raw logs"),
        ("/internal/folder_paths", "folder paths"),
        ("/customnode/getlist", "custom node list"),
        ("/workflow_templates", "workflow templates"), ("/api/userdata", "user data"),
    ],
    "MCP server (SSE / HTTP)": [
        ("/sse", "SSE tool stream"), ("/mcp", "JSON-RPC endpoint"),
        ("/message", "SSE message endpoint"),
    ],
    "Jupyter Notebook": [
        ("/api", "server version"), ("/api/status", "status"),
        ("/api/sessions", "running sessions"), ("/api/contents", "notebooks"),
        ("/api/kernels", "kernels"), ("/api/kernelspecs", "kernel specs"),
        ("/api/terminals", "terminals"), ("/lab", "lab UI"), ("/tree", "tree UI"),
    ],
    "LangServe": [
        ("/openapi.json", "route list"), ("/input_schema", "input schema"),
        ("/output_schema", "output schema"), ("/config_schema", "config schema"),
        ("/playground", "playground"),
    ],
    "Haystack / hayhooks": [
        ("/status", "status"), ("/openapi.json", "route list"),
        ("/pipelines", "deployed pipelines"), ("/docs", "API docs"),
    ],
    "OpenLLM": [
        ("/v1/models", "models"), ("/readyz", "readiness"),
        ("/openapi.json", "route list"), ("/metrics", "metrics"),
        ("/v1/chat/completions", "chat completions"),
    ],
    "SuperAGI": [("/", "console"), ("/health", "health"), ("/api/", "API root")],
    "Chainlit app": [
        ("/project/settings", "settings"), ("/", "landing"), ("/user", "current user"),
    ],
    "Letta / MemGPT": [
        ("/v1/health/", "health"), ("/v1/agents/", "agents"),
        ("/v1/models/", "models"), ("/v1/tools/", "tools"),
        ("/v1/sources/", "sources"), ("/v1/blocks/", "memory blocks"),
        ("/v1/tags/", "tags"),
    ],
    "AutoGen Studio": [("/", "landing"), ("/docs", "API docs"), ("/api/", "API root")],
}

# Paths probed for an unidentified OpenAI-compatible service
GENERIC_ENDPOINTS = [
    ("/openapi.json", "route list"), ("/docs", "API docs"),
    ("/v1/models", "models"), ("/health", "health"), ("/", "landing"),
]

# Standard OpenAI-compatible surface — probed automatically for ANY service
# where /v1/models is live (Ollama, vLLM, LocalAI, LiteLLM, LM Studio,
# TabbyAPI, Aphrodite, ...). POST-only routes answer HTTP 405 (fail-safe: no
# request body is ever sent).
OPENAI_COMPAT_ENDPOINTS = [
    ("/v1/models", "models"), ("/v1/chat/completions", "chat completions"),
    ("/v1/completions", "legacy completions"), ("/v1/embeddings", "embeddings"),
    ("/v1/audio/transcriptions", "audio transcriptions"),
    ("/v1/audio/speech", "text to speech"),
    ("/v1/images/generations", "image generations"),
    ("/v1/moderations", "moderations"), ("/v1/rerank", "rerank"),
    ("/v1/responses", "responses API"),
]

# ---------------------------------------------------------------------------
# AGGRESSIVE PATH SWEEP — segments combined with live API prefixes, used for a
# detected service that has NO OpenAPI spec (otherwise the spec already gives
# the complete route list). Only GET is issued; 404s are dropped; the catch-all
# (SPA) guard disables the sweep entirely for such servers.
# ---------------------------------------------------------------------------
# Prefix sets combined with SWEEP_SEGMENTS. NORMAL is the quick set; ALL is the
# full set of usable API prefixes.
SWEEP_PREFIXES_NORMAL = ["/api", "/api/v1", "/v1"]

SWEEP_PREFIXES_ALL = [
    "/",                  # service exposing routes at the root
    # generic API versioning
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/v1", "/v2", "/v3", "/latest/api", "/api/latest",
    # REST / RPC
    "/rest", "/rest/api", "/api/rest", "/jsonapi", "/rpc", "/jsonrpc",
    # admin / console / internal
    "/admin", "/admin/api", "/api/admin",
    "/console", "/console/api", "/api/console",
    "/internal", "/api/internal", "/v1/internal", "/api/v1/internal",
    "/api/extra", "/management", "/mgmt", "/_debug", "/_admin",
    # service / gateway
    "/services", "/service", "/gateway", "/api/services", "/apis",
    # auth / identity
    "/auth", "/api/auth", "/v1/auth", "/oauth", "/oauth2",
    "/api/oauth", "/api/oauth2", "/oauth/token", "/token", "/api/token",
    "/realms", "/auth/realms", "/sso", "/openid", "/session", "/api/session",
    # kubernetes / cloud control planes
    "/k8s", "/kubernetes", "/api/kubernetes", "/api/v1/namespaces",
    "/v1/namespaces", "/namespaces",
    "/metadata", "/metadata/v1", "/computeMetadata", "/computeMetadata/v1",
    # misc
    "/x/api", "/wp-json", "/wp/index.php", "/debug", "/actuator",
]

# Standalone well-known paths probed once (not prefix+segment combinations)
SWEEP_EXTRA_PATHS = [
    "/graphql", "/api/graphql", "/graphiql", "/rpc", "/jsonrpc",
    "/swagger.json", "/openapi.json", "/docs", "/redoc",
    "/health", "/healthz", "/readyz", "/livez", "/metrics", "/version",
    "/status", "/actuator", "/actuator/health", "/actuator/info",
    "/actuator/env", "/actuator/mappings", "/actuator/beans",
    "/.well-known/openid-configuration", "/.well-known/jwks.json",
    "/apis", "/api/v1/namespaces", "/api/v1/services",
]

SWEEP_SEGMENTS = [
    "version", "health", "healthz", "readyz", "status", "info", "config",
    "settings", "models", "model", "tags", "ps", "tasks", "jobs", "workflows",
    "flows", "pipelines", "agents", "sessions", "chatflows", "tools",
    "credentials", "variables", "nodes", "assistants", "leads", "users", "me",
    "whoami", "auth", "login", "queue", "history", "logs", "metrics", "stats",
    "system", "system_stats", "extensions", "features", "embeddings", "prompt",
    "documents", "workspaces", "threads", "conversations", "runs", "executions",
    "datasets", "sources", "blocks", "traces", "experiments", "feedback",
    "admin", "keys", "tokens", "endpoints", "integrations", "providers",
    "apikeys", "files", "blobs", "import", "export", "search", "query",
    "generate", "chat", "completions", "completion", "embed", "memory",
    "audit", "audit-logs", "reports", "webhooks", "notifications", "knowledge",
    "datasources", "chunks", "vector", "vectors", "index", "collections",
    "tables", "databases", "queries", "projects", "organizations", "teams",
    "roles", "permissions", "groups", "billing", "invoices", "orders",
    # kubernetes / cloud control planes
    "namespaces", "pods", "nodes", "deployments", "replicasets", "statefulsets",
    "daemonsets", "cronjobs", "ingresses", "networkpolicies", "serviceaccounts",
    "clusterroles", "rolebindings", "persistentvolumes", "persistentvolumeclaims",
    "storageclasses", "leases", "endpointslices", "watch", "proxy", "exec",
    "api", "apis", "kinds", "resources", "crds", "livez", "volumes",
    "configmaps", "secrets",
    # SaaS / tenancy
    "subscriptions", "accounts", "tenants", "plans", "usage", "quotas",
    "limits", "members", "invitations", "connections", "schedules", "triggers",
    "hooks", "activity", "alerts", "incidents", "dashboards", "widgets",
    "traces", "spans", "oidc", "saml", "tokens", "sessions", "nonce",
]

# Fast lookup of the union of all default ports
ALL_PORTS = sorted({p for s in SIGNATURES for p in s["ports"]})

# OpenAI-compatible /v1/models fallback probe used on any open port
GENERIC_PROBE = {
    "service": "OpenAI-compatible API",
    "category": "llm-inference",
    "path": "/v1/models",
    "match": [C_STATUS(200), C_JSON_VALUE("object", "list"), C_JSON_KEY("data")],
    "commands": [
        ("List models", "curl -s {url}/v1/models"),
    ],
    "notes": "Generic OpenAI-compatible inference endpoint detected.",
    "severity_noauth": "high",
}
