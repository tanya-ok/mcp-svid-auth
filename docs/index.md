<p class="project-kicker">Workload identity / OAuth</p>

# Give agents access that expires.

<p class="project-lead">An agent proves its identity, gets permission for one server and calls only the tools it is allowed to use. No static API key.</p>

## How it works

```mermaid
---
config:
  theme: base
  themeVariables:
    primaryTextColor: '#183452'
    textColor: '#183452'
    lineColor: '#7b8797'
    edgeLabelBackground: '#e8effa'
    fontFamily: 'Arial, sans-serif'
    fontSize: '15px'
  flowchart:
    nodeSpacing: 24
    rankSpacing: 28
    padding: 12
---
flowchart TB
    accTitle: Short-lived access for an AI agent
    accDescr: SPIRE gives the agent an identity. The access service checks policy and issues a token for one server. The MCP server checks the token and tool permission.
    I["SPIRE<br/>Short-lived identity"] --> A["AI agent"]
    A -->|Identity| P["Access service<br/>Checks policy"]
    P -->|Token| A
    A -->|Tool call| M["MCP server<br/>Checks token + tool"]
    M --> R["Allow or refuse"]
    classDef source fill:#e8effa,stroke:#5276a2,color:#183452,stroke-width:1.5px
    classDef core fill:#e0f3ec,stroke:#328267,color:#173f33,stroke-width:1.5px
    classDef limit fill:#fff0dc,stroke:#b27b36,color:#63421d,stroke-width:1.5px
    class I,A source
    class P,M core
    class R limit
```

[Run the demo](quickstart.md){ .overview-link }
[Technical architecture](architecture.md){ .overview-link }
[Security limits](security.md){ .overview-link }

## Where ZITADEL fits

**People: ZITADEL → sign-in gate → read-only Headlamp.**
**Agents: SPIRE → access service → MCP tools.**

[Human sign-in and passkey boundaries](passwordless-identity.md).
Human-to-agent delegation is not implemented; real Google sign-in and physical passkey enrollment remain operator gates.

!!! note "Scope"
    Prototype. Identity proves the workload, not the human intent.
