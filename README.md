```
 █████╗  ██████╗ ███████╗███╗   ██╗████████╗███████╗ ██████╗  █████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ███████╗██║     ███████║██╔██╗ ██║
██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
      made by JohnDoeAnon in collaboration with AnonymousITALIA
```

# AgentScan

**Read-only scanner for exposed AI / LLM / agent services.**

AgentScan finds AI services listening on standard ports that answer **without
authentication**, identifies what they are, and enumerates their **API
endpoints** — so you can see exactly what is exposed. It never writes, never
sends prompts, and never executes anything on the target: **only HTTP GET**
requests are issued.

Use it **only against assets you own or are explicitly authorised to test.**

## Features

- **31 service signatures** — Ollama, vLLM, LocalAI, LiteLLM, llama.cpp, TGI,
  KoboldCpp, LM Studio, TabbyAPI, Aphrodite, Xinference, Text-Generation-WebUI,
  Flowise, Langflow, n8n, Dify, AnythingLLM, Open WebUI, Gradio, Streamlit,
  ComfyUI, MCP servers, Jupyter, LangServe, Haystack/hayhooks, OpenLLM,
  SuperAGI, Chainlit, Letta/MemGPT, AutoGen Studio.
- **Endpoint enumeration** from five sources: OpenAPI (`/openapi.json`),
  per-service catalog, the shared OpenAI-compatible surface, an aggressive
  path sweep, and fingerprinting evidence.
- **Aggressive path sweep** — 68 API prefixes × 152 segments (+ 27 well-known
  paths) to discover endpoints that are not in any catalog.
- **Catch-all / SPA guard** — detects servers that answer 200 to any path, so
  endpoint lists are never inflated and services are not misidentified.
- **Response snippets** — each live endpoint shows a one-line body preview.
- **Reports** — console, Markdown, JSON, and a CyberStrike-ready payload.
- **Optional response dump** — save the body of every 2xx response for manual
  inspection.
- **Zero dependencies** — standard library only, Python 3.8+.

## Install

```bash
pip install agentscan-py
```
(run with the `agentscan` command)

> Note: the distribution name is `agentscan-py` because `agentscan` is already
> taken on PyPI by an unrelated project.

Or from source:

```bash
git clone https://github.com/JohnDoeAnonITA/agentscan-py.git
cd agentscan-py
pip install .
```

## Usage

```bash
# scan a single host on the built-in AI/agent ports
agentscan -t 10.0.0.5 --authorized

# a subnet
agentscan -t 10.0.0.0/24 --authorized --rate 100 --out-dir ./reports

# specific ports
agentscan -t 10.0.0.5 --authorized --ports 11434,3000,5678,8000

# targets from a file
agentscan --targets hosts.txt --authorized
```

`--authorized` is **mandatory** — it is your confirmation that you are allowed
to test the supplied targets.

### Output

`--out-dir DIR` writes `agentscan-<timestamp>.json`, `.md`, and
`.cyberstrike.json`. You can also write a single format with `--json`,
`--md`, or `--cyberstrike`.

By default only endpoints returning **2xx** are displayed; pass
`--all-status` to also show 401/403/405 (auth / method-not-allowed).

### Key options

| Option | Description |
|---|---|
| `-t, --target` | host / IP / CIDR / range (repeatable, comma-separated) |
| `--targets FILE` | one target per line (`#` comments allowed) |
| `--ports` | `auto`, a list (`11434,3000`), or a range (`8000-8100`) |
| `--sweep {off,normal,aggressive}` | path-sweep depth (default `aggressive`) |
| `--sweep-budget N` | max sweep requests per service |
| `--all-status` | show non-2xx endpoints too |
| `--dump-response --dump-dir DIR` | save body of every 2xx response |
| `--rate N` | global requests/second (default 50) |
| `--cyberstrike FILE` | write CyberStrike ingestion payload |
| `--authorized` | **required** scope confirmation |

Run `agentscan --help` for the full list.

## Target formats

```
10.0.0.5                 single IP (IPv4/IPv6)
box.lab.internal         hostname (DNS)
10.0.0.0/24              CIDR subnet (capped by --max-hosts)
10.0.0.1-10.0.0.50       IP range (explicit end)
10.0.0.1-50              IP range (last-octet shorthand)
```

## Safety

- **Read-only**: only GET requests. POST-only routes are reported as HTTP 405
  (proof the function exists) but never called.
- **Rate-limited** globally (`--rate`).
- **Host cap** on CIDR expansion (`--max-hosts`).
- **Authorization gate** (`--authorized`).

## Output example

```
NO-AUTH! 127.0.0.1:11434  Ollama [high] 6/23 endpoints (2xx)
           GET  /api/tags      200  [{"name":"llama3:latest", ...}]
           GET  /api/version   200  "0.32.5"
           GET  /v1/models     200  {"object":"list","data":[ ... ]}
```

## License

MIT
