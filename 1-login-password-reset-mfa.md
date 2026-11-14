# Threat Model 1: Login + Password Reset + MFA

## 1. System Description
Web + mobile app. Users log in with email + password, optional TOTP(time based one time password) MFA. "Forgot password" sends a reset link by email. Sessions live in Redis, users in a SQL DB. Email provider is third party.

## 2. Assets
- Passwords / hashes
- Session tokens
- Reset tokens
- MFA secrets, backup codes
- User PII, and the account itself

## 3. DFD with Trust Boundaries

```mermaid
flowchart LR
  subgraph TB1["TRUST BOUNDARY 1: User device / Internet (untrusted)"]
    U["User Browser / App"]
  end
  subgraph TB2["TRUST BOUNDARY 2: Our Backend (trusted)"]
    P1(("P1 Login"))
    P2(("P2 MFA Verify"))
    P3(("P3 Reset Request"))
    P4(("P4 Reset Confirm"))
    D1[("D1 User DB")]
    D2[("D2 Session Store - Redis")]
  end
  subgraph TB3["TRUST BOUNDARY 3: Email Provider (3rd party)"]
    M["Email Service + Mailbox"]
  end
  U -->|"1. email + password"| P1
  P1 -->|"2. lookup + verify hash"| D1
  P1 -->|"3. MFA required"| P2
  U -->|"4. TOTP code"| P2
  P1 -->|"5. create session"| D2
  P2 -->|"5b. create session after MFA"| D2
  U -->|"6. forgot password"| P3
  P3 -->|"7. store hashed reset token"| D1
  P3 -->|"8. send reset mail"| M
  M -->|"9. reset link"| U
  U -->|"10. token + new password"| P4
  P4 -->|"11. update hash"| D1
  P4 -->|"12. revoke sessions"| D2

  classDef ext fill:#eeeeee,stroke:#555,color:#000
  classDef proc fill:#cfe8ff,stroke:#1f5f9f,color:#000
  classDef store fill:#fff2b3,stroke:#9a7d0a,color:#000
  class U,M ext
  class P1,P2,P3,P4 proc
  class D1,D2 store
  style TB1 fill:#fff5f5,stroke:#d62728,stroke-width:2px,stroke-dasharray:6 4,color:#000
  style TB2 fill:#f2f8ff,stroke:#1f77b4,stroke-width:2px,stroke-dasharray:6 4,color:#000
  style TB3 fill:#fff9ee,stroke:#e08a00,stroke-width:2px,stroke-dasharray:6 4,color:#000
```

## 4. STRIDE per Element

| Element             | Type     |  S  |  T  |  R  |  I  |  D  |  E  | Threat                                                                        |
| ------------------- | -------- | :-: | :-: | :-: | :-: | :-: | :-: | ----------------------------------------------------------------------------- |
| User Browser / App  | External |  ✔  |     |  ✔  |     |     |     | Phishing, password reuse, user denies actions                                 |
| Flow 1 (creds)      | Flow     |     |  ✔  |     |  ✔  |  ✔  |     | Sniffing / TLS downgrade, login flood                                         |
| P1 Login            | Process  |  ✔  |  ✔  |  ✔  |  ✔  |  ✔  |  ✔  | Credential stuffing, user enumeration, no audit log, lockout DoS, SQLi bypass |
| P2 MFA Verify       | Process  |  ✔  |  ✔  |     |     |  ✔  |  ✔  | OTP brute force, skip MFA step, response tampering                            |
| P3 Reset Request    | Process  |  ✔  |  ✔  |     |  ✔  |  ✔  |     | Host header poisoning, enumeration, email bombing                             |
| P4 Reset Confirm    | Process  |  ✔  |  ✔  |  ✔  |     |     |  ✔  | Weak/reusable token, sessions not revoked                                     |
| D1 User DB          | Store    |     |  ✔  |  ✔  |  ✔  |  ✔  |     | Hash theft (SQLi/insider), tampered reset tokens                              |
| D2 Session Store    | Store    |  ✔  |  ✔  |     |  ✔  |  ✔  |     | Session theft/forgery, Redis open without auth                                |
| Flow 9 (reset link) | Flow     |     |  ✔  |     |  ✔  |     |     | Token leaks via mailbox, Referer, logs                                        |
| Email Provider      | External |  ✔  |     |  ✔  |  ✔  |     |     | Provider sees reset links, compromise = takeover                              |

## 5. Attack Tree: Account Takeover

```mermaid
flowchart TD
  G["GOAL: Take over victim account"]:::goal
  G --> A["Get the password"]
  G --> B["Abuse password reset"]
  G --> C["Bypass MFA"]
  G --> D["Hijack session"]
  A --> A1["Credential stuffing"]
  A --> A2["Phishing page"]
  A --> A3["Brute force weak password"]
  B --> B1["Host header poisoning"]
  B --> B2["Predict or reuse reset token"]
  B --> B3["Read victim mailbox"]
  C --> C1["Brute force OTP, no limit"]
  C --> C2["Skip MFA step"]
  C --> C3["SIM swap on SMS OTP"]
  D --> D1["Steal cookie via XSS"]
  D --> D2["Session fixation"]
  D --> D3["Old session alive after password change"]
  classDef goal fill:#d62728,color:#fff,stroke:#8b0000
```
*All branches are OR: any one path is enough.*

## 6. Mitigations

| Threat                            | Mitigation                                                                                               |
| --------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Credential stuffing / brute force | Rate limit per IP + per account, CAPTCHA after N fails, breached-password check, MFA                     |
| User enumeration                  | Same generic message and response time everywhere                                                        |
| Weak reset token                  | 128-bit CSPRNG token, store only its hash, 15 min expiry, single use                                     |
| MFA bypass                        | Enforce MFA state server-side on every route, OTP attempt cap + expiry, prefer TOTP/WebAuthn over SMS    |
| Session issues                    | Rotate session ID on login, revoke all sessions on password change, HttpOnly + Secure + SameSite cookies |

