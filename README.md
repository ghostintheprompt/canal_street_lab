# canal_street_lab

A counterfeit check for AP2-style agent payment mandates.

Canal Street taught everyone one thing about a good fake: it does not have to
be perfect, it just has to pass at the counter. The same is true of a signed
agent payment authorization. A valid signature proves the bytes were not
altered. It does not prove the authority was scoped so it cannot be reused,
escalated, or replayed past the one purchase it was signed for.

This is a static lint for [AP2](https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol)
mandates, all three types. It reads structure and flags the field-level
weaknesses that let a signed mandate keep working. It is deliberately honest
about what structure cannot decide.

stdlib only. No dependencies, no network, no API key.

## Why this exists

As retailers hand AI agents the ability to shop and pay on a customer's
behalf, the authorization layer is where agent fraud concentrates. AP2 wraps
each purchase in signed, verifiable-credential mandates that progressively
refine authority:

- **Intent Mandate** — the user's high-level goal and its hard constraints
  (spend cap, allowed merchants, expiry, whether the agent may act with no
  human present).
- **Cart Mandate** — the exact items, totals, and merchant for one purchase,
  chained back to an Intent Mandate.
- **Payment Mandate** — the minimal subset handed to the network, pointing
  back to a reviewed cart and a tokenized payment instrument.

Those fields are only protective when they are tight and actually checked. A
wildcard merchant scope, a missing spend cap, a human-not-present intent with
no ceiling, a payment detached from its cart, a raw card number where a token
belongs, a missing nonce, or a multi-day expiry turns a scoped authorization
into a standing, reusable blank check that is still cryptographically valid.

Published work already treats this as a live surface: the arXiv paper
"Whispers of Wealth: Red-Teaming Google's Agent Payments Protocol via Prompt
Injection" and Palo Alto Unit 42's reporting on agentic retail fraud (an
agent able to self-trigger refunds lets a ring push on the order of 10,000
returns in an hour). This lab is the small defensive counterpart: run the
check on your mandates before the structure bites you.

## The checks

Each finding carries the code, the plain-language reason, and the closest CWE.

**All mandate types**

| Code | CWE | What it means |
|------|-----|----------------|
| `REPLAYABLE` | CWE-294 | No `nonce`; the same mandate can be submitted repeatedly |
| `UNVERIFIED_PRESENCE` | CWE-287 | `human_present: true` with no `presence_evidence` to check |

**Intent Mandate**

| Code | CWE | What it means |
|------|-----|----------------|
| `UNBOUND_AGENT` | CWE-639 | No `agent_id`; any agent can present the mandate |
| `WILDCARD_SCOPE` | CWE-863 | `allowed_merchants` empty or `*`; spendable anywhere |
| `NO_SPEND_CAP` | CWE-770 | No `max_amount`/`max_price`; unbounded spend |
| `AUTONOMOUS_BROAD` | CWE-269 | Human-not-present intent with wildcard or uncapped scope; standing spend authority |
| `LONG_TTL` | CWE-613 | `expiry` far out; a standing authorization |

**Cart Mandate**

| Code | CWE | What it means |
|------|-----|----------------|
| `UNBOUND_AGENT` | CWE-639 | No `agent_id`; any agent can present the mandate |
| `NO_INTENT_CHAIN` | CWE-345 | No `intent_ref`; the cart authorizes itself |
| `WILDCARD_SCOPE` | CWE-863 | `allowed_merchants` empty or `*`; spendable anywhere |
| `LOOSE_CEILING` | CWE-863 | `max_amount` far above the cart total; escalation headroom |
| `LONG_TTL` | CWE-613 | `expiry` far out; a one-shot authorization becomes a standing token |

**Payment Mandate**

| Code | CWE | What it means |
|------|-----|----------------|
| `NO_CART_LINK` | CWE-345 | No `cart_ref`; payment detached from any reviewed cart |
| `UNHASHED_METHOD` | CWE-311 | `payment_method` looks like a raw card number, not a tokenized ref |
| `NO_METHOD_REF` | CWE-345 | No `payment_method_ref`; nothing ties the charge to a vaulted instrument |

CWE mappings are the nearest-fit weakness class, not a claim of an assigned ID.

## Blind spots (on purpose)

The lint reads structure. It cannot decide, and does not pretend to:

- **Signature validity** — confirming the proof is genuine needs the issuer's key.
- **Intent authenticity** — a reference is checked for presence, not that it
  chains to a real user-signed upstream mandate.
- **Presence truth** — `presence_evidence` is checked for existence, not that a
  human actually authorized at transaction time.

Those three are the hard problems. A static check that claimed to solve them
would be its own counterfeit. What this does is catch the forgeries that pass
today because nobody read the fields, which is most of them.

## Usage

```
python3 mandate_lint.py                 # lint everything in samples/
python3 mandate_lint.py path/to/*.json  # lint specific mandates
python3 -m unittest -v                  # run the test suite
```

Exit code is non-zero if any mandate fails, so it can gate CI.

## Sample output

```
[PASS] clean-store-purchase  <CartMandate>
[FAIL] holiday-wildcard  <CartMandate>  (5 issues)
         - WILDCARD_SCOPE (CWE-863): allowed_merchants is empty or '*'; reusable at any merchant
         - LOOSE_CEILING (CWE-863): max_amount 50000.00 >> cart total 4200.00; escalation headroom
         - REPLAYABLE (CWE-294): no nonce; same mandate can be submitted repeatedly
         - LONG_TTL (CWE-613): expiry 132h out (> 24h); standing token
         - UNVERIFIED_PRESENCE (CWE-287): human_present=true with no presence_evidence to check
[FAIL] intent-autonomous-open  <IntentMandate>  (5 issues)
         - WILDCARD_SCOPE (CWE-863): allowed_merchants is empty or '*'; reusable at any merchant
         - NO_SPEND_CAP (CWE-770): no max_amount/max_price; intent authorizes unbounded spend
         - AUTONOMOUS_BROAD (CWE-269): human-not-present intent with wildcard/uncapped scope; standing spend authority
         - REPLAYABLE (CWE-294): no nonce; same mandate can be submitted repeatedly
         - LONG_TTL (CWE-613): expiry 132h out (> 24h); standing token
[PASS] intent-scoped  <IntentMandate>
[FAIL] payment-detached  <PaymentMandate>  (4 issues)
         - NO_CART_LINK (CWE-345): no cart_ref; payment is detached from any reviewed cart
         - UNHASHED_METHOD (CWE-311): payment_method looks like a raw card number, not a tokenized ref
         - REPLAYABLE (CWE-294): no nonce; same mandate can be submitted repeatedly
         - UNVERIFIED_PRESENCE (CWE-287): human_present=true with no presence_evidence to check
[PASS] payment-linked  <PaymentMandate>
[FAIL] unbound-self-authorizing  <CartMandate>  (4 issues)
         - UNBOUND_AGENT (CWE-639): no agent_id; any agent can present this mandate
         - NO_INTENT_CHAIN (CWE-345): no intent_ref; cart authorizes itself
         - REPLAYABLE (CWE-294): no nonce; same mandate can be submitted repeatedly
         - UNVERIFIED_PRESENCE (CWE-287): human_present=true with no presence_evidence to check

3/7 mandates passed the counterfeit check.
```

## License

MIT. See [LICENSE](LICENSE).
