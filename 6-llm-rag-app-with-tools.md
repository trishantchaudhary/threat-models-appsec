# Threat Model 6: LLM App (RAG Chatbot with Tools)

## 1. System Description
Chatbot backend takes a user prompt, retrieves documents from a vector DB (RAG), calls an LLM API, and may call tools (SQL, email, code execution, web). Documents are ingested from internal files and external content. Chat history is stored.

## 2. Assets
- Knowledge base and chat history (sensitive data)
- System prompt, API keys, tool credentials
- What the tools can do (send email, run queries)
- Model API budget and availability

## 3. DFD with Trust Boundaries

```mermaid
flowchart LR
  subgraph TB1["TRUST BOUNDARY 1: User (untrusted)"]
    U["User"]
  end
  subgraph TB2["TRUST BOUNDARY 2: Our Backend (trusted)"]
    P1(("P1 Chat Frontend"))
    P2(("P2 Orchestrator / Agent"))
    P3(("P3 Tools: SQL, Email, Code, Web"))
    P4(("P4 Ingestion Pipeline"))
    D1[("D1 Vector DB")]
    D2[("D2 Chat History + Logs")]
  end
  subgraph TB3["TRUST BOUNDARY 3: LLM Provider (3rd party)"]
    L["LLM API"]
  end
  subgraph TB4["TRUST BOUNDARY 4: Untrusted External Content"]
    W["Web pages, PDFs, emails, uploads"]
  end
  U -->|"1. prompt"| P1
  P1 -->|"2. user message"| P2
  P2 -->|"3. retrieve chunks"| D1
  P2 -->|"4. prompt + context"| L
  L -->|"5. response + tool requests"| P2
  P2 -->|"6. tool calls"| P3
  P3 -->|"7. browse / fetch"| W
  W -->|"8. documents"| P4
  P4 -->|"9. embeddings"| D1
  P2 -->|"10. store chat"| D2
  P2 -->|"11. answer"| P1
  P1 -->|"12. rendered output"| U

  classDef ext fill:#eeeeee,stroke:#555,color:#000
  classDef proc fill:#cfe8ff,stroke:#1f5f9f,color:#000
  classDef store fill:#fff2b3,stroke:#9a7d0a,color:#000
  class U,L,W ext
  class P1,P2,P3,P4 proc
  class D1,D2 store
  style TB1 fill:#fff5f5,stroke:#d62728,stroke-width:2px,stroke-dasharray:6 4,color:#000
  style TB2 fill:#f2f8ff,stroke:#1f77b4,stroke-width:2px,stroke-dasharray:6 4,color:#000
  style TB3 fill:#fff9ee,stroke:#e08a00,stroke-width:2px,stroke-dasharray:6 4,color:#000
  style TB4 fill:#fff5f5,stroke:#d62728,stroke-width:2px,stroke-dasharray:6 4,color:#000
```

## 4. STRIDE per Element

| Element | Type | S | T | R | I | D | E | Threat |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|---|
| User | External | ✔ | | ✔ | | | | Jailbreak attempts, injected text pretending to be "system" |
| P1 Chat Frontend | Process | | ✔ | | ✔ | | | LLM output rendered as HTML / markdown (XSS, image exfiltration) |
| P2 Orchestrator / Agent | Process | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Prompt injection, system prompt leak, endless agent loops, no per-user limits |
| P3 Tools | Process | ✔ | ✔ | ✔ | ✔ | | ✔ | Excessive agency: injected text triggers email / SQL / code with broad creds |
| P4 Ingestion Pipeline | Process | | ✔ | | | | | Poisoned documents enter the knowledge base |
| D1 Vector DB | Store | | ✔ | | ✔ | | | No ACL on retrieval (cross-user leak), poisoned chunks, embedding inversion |
| D2 Chat History + Logs | Store | | | ✔ | ✔ | | | PII / secrets stored in logs, no record of which prompt caused a tool call |
| LLM API | External | | | | ✔ | ✔ | | Data sent to provider, outage, malicious or swapped model |
| Web / PDFs / emails | External | ✔ | ✔ | | | | | Hidden instructions (indirect prompt injection) |
| Flow 5 (tool requests) | Flow | ✔ | ✔ | | | | ✔ | Model output treated as trusted command |
| Flow 12 (rendered output) | Flow | | ✔ | | ✔ | | | Secrets leaked in image URL / link query string |

## 5. Attack Tree: Make the App Leak Data or Act for the Attacker

```mermaid
flowchart TD
  G["GOAL: Leak data or make the agent act for attacker"]:::goal
  G --> A["Direct prompt injection"]
  G --> B["Indirect prompt injection"]
  G --> C["Poison / abuse RAG"]
  G --> D["Abuse model output"]
  G --> E["Cost and supply chain"]
  A --> A1["Jailbreak the guardrails"]
  A --> A2["Extract system prompt"]
  B --> B1["Hide instructions in web page / PDF / email"]
  B1 --> B2["Agent reads it and follows it"]
  B2 --> B3["Tool call: email data, query DB"]
  B2 --> B4["Markdown image with secret in URL"]
  C --> C1["Retrieve another user's documents, no ACL"]
  C --> C2["Plant poisoned doc in knowledge base"]
  D --> D1["LLM output renders as XSS"]
  D --> D2["LLM output passed into SQL / shell"]
  E --> E1["Denial of wallet: huge prompts / loops"]
  E --> E2["Malicious model, plugin or dataset"]
  classDef goal fill:#d62728,color:#fff,stroke:#8b0000
```
*Branches are OR. The B1 to B3/B4 chain is sequential: each step needs the one before.*

## 6. Mitigations

| Threat | Mitigation |
|---|---|
| Prompt injection (direct + indirect) | No perfect fix, so layer: separate instructions from untrusted data, label retrieved content, filters on input/output, and assume the model can be tricked |
| Excessive agency | Least privilege per tool, read-only by default, per-user scoped credentials, human approval for send / delete / pay |
| Cross-user RAG leakage | ACL-aware retrieval: filter by user / tenant before the LLM sees anything, per-tenant indexes |
| Improper output handling | Treat LLM output as untrusted input: encode for HTML, parameterize SQL, never eval / shell it, validate structured output with a schema |
| Markdown / link exfiltration | Block or proxy external images and links, CSP `img-src` allowlist, strip URLs with query data |
| Data poisoning | Vet and sign data sources, review ingestion, monitor retrieval for anomalies |
| System prompt leakage | Never put secrets or authorization logic in the prompt, assume it is public |
| Cost / DoS | Per-user rate and token limits, max output length, agent step limits, budget alerts |
| Supply chain | Pin and verify model / package hashes, SBOM, trusted registries only |
| Visibility | Log prompts, retrieved chunks, tool calls (with redaction), red-team regularly |
