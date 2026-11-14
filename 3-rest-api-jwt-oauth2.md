# Threat Model 3: REST API with JWT / OAuth 2.0

## 1. System Description
Mobile app / SPA calls a REST API. Login goes through an OAuth 2.0 / OIDC authorization server (Authorization Code + PKCE). The API gateway validates the JWT access token, the resource API reads the DB.

## 2. Assets
- Access / refresh tokens, signing keys
- User data behind the API
- Client secrets, scopes, consent records
- API availability

## 3. DFD with Trust Boundaries

```mermaid
flowchart LR
  subgraph TB1["TRUST BOUNDARY 1: Client device (untrusted)"]
    A["Mobile App / SPA"]
  end
  subgraph TB2["TRUST BOUNDARY 2: Our Backend (trusted)"]
    P1(("P1 Authorization Server"))
    P2(("P2 API Gateway"))
    P3(("P3 Resource API"))
    D1[("D1 Users + Consent DB")]
    D2[("D2 App Data DB")]
  end
  A -->|"1. auth request + PKCE challenge"| P1
  P1 -->|"2. authorization code"| A
  A -->|"3. code + PKCE verifier"| P1
  P1 -->|"4. access + refresh token"| A
  P1 -->|"5. verify user / consent"| D1
  A -->|"6. request + Bearer token"| P2
  P2 -->|"7. validated request"| P3
  P3 -->|"8. query data"| D2

  classDef ext fill:#eeeeee,stroke:#555,color:#000
  classDef proc fill:#cfe8ff,stroke:#1f5f9f,color:#000
  classDef store fill:#fff2b3,stroke:#9a7d0a,color:#000
  class A ext
  class P1,P2,P3 proc
  class D1,D2 store
  style TB1 fill:#fff5f5,stroke:#d62728,stroke-width:2px,stroke-dasharray:6 4,color:#000
  style TB2 fill:#f2f8ff,stroke:#1f77b4,stroke-width:2px,stroke-dasharray:6 4,color:#000
```

## 4. STRIDE per Element

| Element | Type | S | T | R | I | D | E | Threat |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|---|
| Mobile App / SPA | External | ✔ | ✔ | ✔ | ✔ | | | Token stored insecurely (localStorage), reverse-engineered secrets, user denies actions |
| Flow 1-3 (OAuth) | Flow | ✔ | ✔ | | ✔ | | | Code interception (no PKCE), loose redirect_uri, missing state |
| Flow 4 (tokens) | Flow | ✔ | | | ✔ | | | Token theft, tokens in logs / URL |
| P1 Authorization Server | Process | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Refresh token reuse, over-broad scopes, client impersonation |
| P2 API Gateway | Process | ✔ | ✔ | | | ✔ | ✔ | JWT alg none / weak key / no exp / no aud check, no rate limit |
| P3 Resource API | Process | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | BOLA, BFLA, mass assignment, excessive data in response |
| D1 Users + Consent DB | Store | | ✔ | ✔ | ✔ | | | Consent tampering, credential leak |
| D2 App Data DB | Store | | ✔ | ✔ | ✔ | ✔ | | Cross-user data access, injection, expensive queries |

## 5. Attack Tree: Access Another User's Data

```mermaid
flowchart TD
  G["GOAL: Access another user's data"]:::goal
  G --> A["Broken authorization"]
  G --> B["Steal a token"]
  G --> C["Forge a token"]
  G --> D["Abuse OAuth flow"]
  A --> A1["BOLA: change object ID"]
  A --> A2["BFLA: call admin endpoint"]
  A --> A3["Mass assignment: role=admin"]
  A --> A4["Old /v1 API without auth"]
  B --> B1["XSS reads localStorage"]
  B --> B2["Token in logs / URL"]
  B --> B3["Steal refresh token, no rotation"]
  C --> C1["alg none"]
  C --> C2["Crack weak HS256 secret"]
  C --> C3["Missing aud / iss check"]
  D --> D1["Loose redirect_uri, steal code"]
  D --> D2["No PKCE, code interception"]
  D --> D3["Missing state, login CSRF"]
  classDef goal fill:#d62728,color:#fff,stroke:#8b0000
```
*All branches are OR.*

## 6. Mitigations

| Threat | Mitigation |
|---|---|
| BOLA | Check ownership on every object access, scope queries by owner |
| BFLA | Central authorization (RBAC/ABAC), deny by default |
| JWT forgery | Pin algorithm, strong key or RS256 with rotation, validate exp / iss / aud, short TTL |
| Token theft | HttpOnly cookie or secure OS storage, strict CSP, never log tokens |
| OAuth flaws | Auth Code + PKCE only, exact-match redirect_uri, validate state |
| Refresh token theft | Rotation + reuse detection, revoke on logout |
| Mass assignment / data exposure | Response DTOs with allowlisted fields, schema validation rejecting unknown fields |
| No rate limiting | Per user / key / IP limits, pagination caps, query cost limits |
| Old API versions | API inventory, retire old versions, same auth everywhere |
