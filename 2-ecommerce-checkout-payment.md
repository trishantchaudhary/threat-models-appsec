# Threat Model 2: E-commerce Checkout + Payment (UPI / Card)

## 1. System Description
Customer adds items, applies a coupon, pays through a payment gateway (hosted card/UPI fields). The gateway sends a webhook when payment succeeds, then the order is fulfilled.

## 2. Assets
- Money (orders, refunds)
- Card / UPI data and payment tokens
- Order and customer data
- Inventory and coupon budget
- Gateway API keys + webhook secret

## 3. DFD with Trust Boundaries

```mermaid
flowchart LR
  subgraph TB1["TRUST BOUNDARY 1: Customer device / Internet (untrusted)"]
    C["Customer Browser / App"]
  end
  subgraph TB2["TRUST BOUNDARY 2: Our Backend (trusted)"]
    P1(("P1 Checkout API"))
    P2(("P2 Coupon Service"))
    P3(("P3 Order Service"))
    P4(("P4 Webhook Handler"))
    D1[("D1 Orders + Inventory DB")]
    D2[("D2 Coupon DB")]
  end
  subgraph TB3["TRUST BOUNDARY 3: Payment Gateway (3rd party)"]
    G["Payment Gateway"]
  end
  C -->|"1. cart, qty, coupon"| P1
  P1 -->|"2. redeem coupon"| P2
  P2 -->|"3. mark used"| D2
  P1 -->|"4. create order"| P3
  P3 -->|"5. save order + stock"| D1
  P3 -->|"6. create payment order"| G
  C -->|"7. pay (hosted fields)"| G
  G -->|"8. webhook: payment success"| P4
  P4 -->|"9. mark order paid"| P3

  classDef ext fill:#eeeeee,stroke:#555,color:#000
  classDef proc fill:#cfe8ff,stroke:#1f5f9f,color:#000
  classDef store fill:#fff2b3,stroke:#9a7d0a,color:#000
  class C,G ext
  class P1,P2,P3,P4 proc
  class D1,D2 store
  style TB1 fill:#fff5f5,stroke:#d62728,stroke-width:2px,stroke-dasharray:6 4,color:#000
  style TB2 fill:#f2f8ff,stroke:#1f77b4,stroke-width:2px,stroke-dasharray:6 4,color:#000
  style TB3 fill:#fff9ee,stroke:#e08a00,stroke-width:2px,stroke-dasharray:6 4,color:#000
```

## 4. STRIDE per Element

| Element | Type | S | T | R | I | D | E | Threat |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|---|
| Customer | External | ✔ | | ✔ | | | | Stolen account / cards, carding bots, "I never ordered this" |
| Flow 1 (cart) | Flow | | ✔ | | ✔ | | | Price / qty / currency tampering |
| P1 Checkout API | Process | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Trusts client price, IDOR on orders, card data in logs, bot flood |
| P2 Coupon Service | Process | | ✔ | | | ✔ | ✔ | Coupon stacking, race condition, reuse |
| P3 Order Service | Process | | ✔ | ✔ | | | ✔ | Amount mismatch, double processing, refund abuse |
| P4 Webhook Handler | Process | ✔ | ✔ | ✔ | | ✔ | | Forged webhook, replayed webhook, no signature check |
| D1 Orders + Inventory DB | Store | | ✔ | ✔ | ✔ | ✔ | | Order tampering, PII leak, stock race |
| D2 Coupon DB | Store | | ✔ | | | ✔ | | Double redemption, coupon list leak |
| Flow 7 (payment) | Flow | | ✔ | | ✔ | | | Card data touching our servers, redirect tampering |
| Flow 8 (webhook) | Flow | ✔ | ✔ | | | | | Fake "payment success" call |
| Payment Gateway | External | ✔ | | ✔ | ✔ | ✔ | | Gateway outage, key leak, dispute / chargeback |

## 5. Attack Tree: Get Goods Without Paying Full Price

```mermaid
flowchart TD
  G["GOAL: Get goods without paying full price"]:::goal
  G --> A["Tamper with order"]
  G --> B["Fake the payment"]
  G --> C["Abuse coupons"]
  G --> D["Abuse refunds"]
  A --> A1["Change price in request"]
  A --> A2["Negative or huge quantity"]
  A --> A3["Swap currency"]
  B --> B1["Forge webhook, no signature check"]
  B --> B2["Replay old success webhook"]
  B --> B3["Pay Rs.1, order worth Rs.5000"]
  C --> C1["50 parallel requests, race"]
  C --> C2["Stack multiple coupons"]
  C --> C3["Reuse single-use coupon"]
  D --> D1["Refund then keep goods"]
  D --> D2["Compromised admin account"]
  classDef goal fill:#d62728,color:#fff,stroke:#8b0000
```
*All branches are OR.*

## 6. Mitigations

| Threat                           | Mitigation                                                                        |
| -------------------------------- | --------------------------------------------------------------------------------- |
| Price / qty tampering            | Server recalculates total from DB prices, validate qty range                      |
| Forged webhook                   | Verify HMAC signature with gateway secret, optionally allowlist gateway IPs       |
| Amount mismatch                  | Compare webhook amount + currency to order, confirm via gateway fetch-payment API |
| Coupon race / reuse              | Atomic redeem (UNIQUE constraint + conditional UPDATE), one coupon per order      |
| IDOR on orders                   | Scope queries by owner: `WHERE id=? AND user_id=?`                                |
| Card data exposure               | Hosted fields / tokenization, never log PAN                                       |
| Refund abuse                     | Dual approval above a limit, RBAC, immutable audit log                            |
