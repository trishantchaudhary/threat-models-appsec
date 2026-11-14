# Threat Models

Each file has the same 6 parts: System Description, Assets, DFD with Trust Boundaries, STRIDE per Element, Attack Tree, Mitigations.

| # | System |
|---|---|
| 1 | Login + Password Reset + MFA |
| 2 | E-commerce Checkout + Payment |
| 3 | REST API with JWT / OAuth 2.0 |
| 4 | File Upload + Sharing Service |
| 5 | 3-Tier Web App on AWS |
| 6 | LLM App (RAG + Tools) |

**DFD legend:** rectangle = external entity, circle = process, cylinder = data store, dashed box = trust boundary.

**STRIDE:** S Spoofing, T Tampering, R Repudiation, I Info disclosure, D Denial of service, E Elevation of privilege.
Per element: external entities get S, R. Processes get all six. Data stores get T, R, I, D. Data flows get T, I, D.

Diagrams are Mermaid: they render on GitHub, VS Code (Markdown Preview Mermaid Support), Obsidian, or paste into https://mermaid.live
