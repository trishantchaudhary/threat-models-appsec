# Threat Model 4: File Upload + Sharing Service (Google Drive style)

## 1. System Description
Users upload files and share them by link. Files go to object storage; a worker scans them and makes previews; recipients download through short-lived signed URLs. Optional "import from URL" feature.

## 2. Assets
- User files
- Share links, signed URLs, ACLs
- Storage and compute budget
- Platform reputation (must not host malware)

## 3. DFD with Trust Boundaries

```mermaid
flowchart LR
  subgraph TB1["TRUST BOUNDARY 1: Users / Internet (untrusted)"]
    UP["Uploader"]
    RC["Recipient"]
  end
  subgraph TB2["TRUST BOUNDARY 2: Our Backend (trusted)"]
    P1(("P1 Upload API"))
    P2(("P2 Share + Download Service"))
    D1[("D1 Metadata + ACL DB")]
    D2[("D2 Object Storage")]
    subgraph TB3["TRUST BOUNDARY 3: Isolated Worker Sandbox"]
      P3(("P3 Scan + Preview Worker"))
    end
  end
  subgraph TB4["TRUST BOUNDARY 4: External Websites"]
    EXT["Remote URL for import"]
  end
  UP -->|"1. upload file"| P1
  P1 -->|"2. metadata + owner"| D1
  P1 -->|"3. store raw file"| D2
  D2 -->|"4. scan / thumbnail job"| P3
  P3 -->|"5. safe copy + preview"| D2
  P3 -->|"6. fetch URL (import)"| EXT
  RC -->|"7. open share link"| P2
  P2 -->|"8. check ACL"| D1
  P2 -->|"9. short-lived signed URL"| RC
  RC -->|"10. download file"| D2

  classDef ext fill:#eeeeee,stroke:#555,color:#000
  classDef proc fill:#cfe8ff,stroke:#1f5f9f,color:#000
  classDef store fill:#fff2b3,stroke:#9a7d0a,color:#000
  class UP,RC,EXT ext
  class P1,P2,P3 proc
  class D1,D2 store
  style TB1 fill:#fff5f5,stroke:#d62728,stroke-width:2px,stroke-dasharray:6 4,color:#000
  style TB2 fill:#f2f8ff,stroke:#1f77b4,stroke-width:2px,stroke-dasharray:6 4,color:#000
  style TB3 fill:#f3fbf5,stroke:#2e8b57,stroke-width:2px,stroke-dasharray:6 4,color:#000
  style TB4 fill:#fff9ee,stroke:#e08a00,stroke-width:2px,stroke-dasharray:6 4,color:#000
```

## 4. STRIDE per Element

| Element | Type | S | T | R | I | D | E | Threat |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|---|
| Uploader | External | ✔ | | ✔ | | | | Stolen session shares files out, uploader denies abuse |
| Recipient | External | ✔ | | ✔ | ✔ | | | Guessed / leaked link, forwarded link |
| Flow 1 (upload) | Flow | | ✔ | | | ✔ | | Malicious content, zip bomb, huge file flood |
| P1 Upload API | Process | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Path traversal in filename, type spoofing, no quota |
| P2 Share + Download | Process | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | IDOR on file ID, weak link tokens, long-lived signed URLs |
| P3 Scan + Preview Worker | Process | | ✔ | | ✔ | ✔ | ✔ | Parser exploit (image/PDF/archive) leads to RCE and cloud creds |
| D1 Metadata + ACL DB | Store | | ✔ | ✔ | ✔ | | | ACL tampering, cross-tenant query bug |
| D2 Object Storage | Store | | ✔ | | ✔ | ✔ | | Public bucket, stored XSS via SVG/HTML, undeleted files |
| Flow 6 (import URL) | Flow | | | | ✔ | | ✔ | SSRF to internal services / cloud metadata |
| Remote URL | External | ✔ | ✔ | | | | | Malicious redirect, hostile content |

## 5. Attack Tree: Steal Files or Run Code on Server

```mermaid
flowchart TD
  G["GOAL: Steal files or run code on server"]:::goal
  G --> A["Access other users' files"]
  G --> B["Upload malicious file"]
  G --> C["Exploit the worker"]
  G --> D["SSRF via import URL"]
  G --> E["Exhaust resources"]
  A --> A1["IDOR: change file ID"]
  A --> A2["Guess share link"]
  A --> A3["Public bucket"]
  A --> A4["Leaked long-lived signed URL"]
  B --> B1["Webshell / polyglot file"]
  B --> B2["SVG or HTML with JS, stored XSS"]
  B --> B3["Path traversal in filename"]
  C --> C1["Crafted image / PDF / archive"]
  C1 --> C2["RCE in worker"]
  C2 --> C3["Steal cloud credentials"]
  D --> D1["Fetch cloud metadata endpoint"]
  D --> D2["Scan internal network"]
  E --> E1["Zip bomb"]
  E --> E2["Upload flood"]
  classDef goal fill:#d62728,color:#fff,stroke:#8b0000
```
*Branches are OR. The C1 to C3 chain is sequential: each step needs the one before.*

## 6. Mitigations

| Threat | Mitigation |
|---|---|
| IDOR / broken ACL | Authorize every file operation server-side, scope queries by owner / tenant |
| Guessable links | 128-bit random tokens, optional expiry + password, revoke button |
| Malicious file | Extension allowlist + magic byte check, random server-side names, AV scan before sharing |
| Stored XSS | Serve user content from a separate domain, `Content-Disposition: attachment`, `nosniff`, CSP sandbox |
| Parser exploit | Sandboxed worker (no network, low privilege, seccomp, CPU/mem/time limits), patch libraries |
| SSRF | Allowlist, block private/link-local IPs, no redirects, isolated egress |
| Path traversal | Never use user filename on disk (`secure_filename` + random name) |
| DoS | Size limits, per-user quotas, rate limits, decompression ratio / depth limits |
| Bucket exposure | Block Public Access, short-lived signed URLs, access logging |
| Leftover data | Soft delete then hard delete job, strip EXIF |
