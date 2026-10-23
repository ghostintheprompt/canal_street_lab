#!/usr/bin/env python3
"""canal_street_lab: a counterfeit check for AP2-style agent payment mandates.

AP2 (Google's Agent Payments Protocol) wraps an agent's purchase in signed
"mandates" that progressively refine authority:

  - Intent Mandate  : the user's high-level goal and its hard constraints.
  - Cart Mandate    : the exact items, totals, and merchant for one purchase.
  - Payment Mandate : the minimal subset handed to the network to move funds.

A valid signature proves the bytes were not altered. It does not prove the
authority was scoped so it cannot be reused, escalated, or replayed past the
one purchase it was signed for. This is a static lint for all three mandate
types. It reads structure and flags the field-level weaknesses that let a
signed mandate keep working. It is deliberately honest about what structure
cannot decide; see BLIND_SPOTS and the README.

stdlib only. Usage:
    python3 mandate_lint.py samples/*.json
    python3 mandate_lint.py            # defaults to everything in samples/
"""

import glob
import json
import re
import sys
from datetime import datetime, timezone
from decimal import Decimal

# A mandate is a scoped authorization. These thresholds decide when a field has
# turned it into a standing, reusable, or escalatable credential.
MAX_TTL_HOURS = 24
MAX_CEILING_MULTIPLE = Decimal("1.5")
# Fixed "now" so sample output is reproducible; swap for datetime.now(tz) live.
NOW = datetime(2026, 12, 20, 12, 0, 0, tzinfo=timezone.utc)

BLIND_SPOTS = [
    "signature validity: needs the issuer's key to confirm the proof is real",
    "intent authenticity: a reference is checked for presence, not that it "
    "chains to a genuinely user-signed upstream mandate",
    "presence truth: presence_evidence is checked for existence, not that a "
    "human actually authorized at transaction time",
]

MANDATE_TYPES = ("IntentMandate", "CartMandate", "PaymentMandate")


def mandate_type(mandate):
    declared = mandate.get("type", [])
    for name in MANDATE_TYPES:
        if name in declared:
            return name
    return "CartMandate"  # sensible default for a bare cart-shaped object


# --- shared field checks, reused across mandate types -----------------------

def _ttl_hours(expiry):
    exp_dt = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
    return (exp_dt - NOW).total_seconds() / 3600


def _check_binding(sub, flag):
    if not sub.get("agent_id"):
        flag("UNBOUND_AGENT", "CWE-639",
             "no agent_id; any agent can present this mandate")


def _check_scope(cons, flag):
    allowed = cons.get("allowed_merchants")
    if not allowed or "*" in allowed:
        flag("WILDCARD_SCOPE", "CWE-863",
             "allowed_merchants is empty or '*'; reusable at any merchant")


def _check_replay(sub, flag):
    if not sub.get("nonce"):
        flag("REPLAYABLE", "CWE-294",
             "no nonce; same mandate can be submitted repeatedly")


def _check_ttl(cons, flag):
    exp = cons.get("expiry")
    if exp and _ttl_hours(exp) > MAX_TTL_HOURS:
        flag("LONG_TTL", "CWE-613",
             f"expiry {_ttl_hours(exp):.0f}h out (> {MAX_TTL_HOURS}h); standing token")


def _check_presence(sub, cons, flag):
    if cons.get("human_present") is True and not sub.get("presence_evidence"):
        flag("UNVERIFIED_PRESENCE", "CWE-287",
             "human_present=true with no presence_evidence to check")


# --- per-type check sets ----------------------------------------------------

def _check_intent(sub, cons, flag):
    _check_binding(sub, flag)
    _check_scope(cons, flag)
    # An Intent Mandate with no spend cap authorizes unbounded spend downstream.
    if cons.get("max_amount") is None and cons.get("max_price") is None:
        flag("NO_SPEND_CAP", "CWE-770",
             "no max_amount/max_price; intent authorizes unbounded spend")
    # Autonomous intent (human-not-present) plus a loose scope is standing
    # self-service spend authority for the agent.
    autonomous = cons.get("human_not_present") is True or cons.get("human_present") is False
    allowed = cons.get("allowed_merchants")
    broad = (not allowed or "*" in allowed
             or cons.get("max_amount") is None and cons.get("max_price") is None)
    if autonomous and broad:
        flag("AUTONOMOUS_BROAD", "CWE-269",
             "human-not-present intent with wildcard/uncapped scope; standing spend authority")
    _check_replay(sub, flag)
    _check_ttl(cons, flag)
    # UNVERIFIED_PRESENCE applies to all mandate types: an intent asserting
    # human_present at authoring time still needs presence_evidence to check.
    _check_presence(sub, cons, flag)


def _check_cart(sub, cons, cart, flag):
    _check_binding(sub, flag)
    if not sub.get("intent_ref"):
        flag("NO_INTENT_CHAIN", "CWE-345",
             "no intent_ref; cart authorizes itself")
    _check_scope(cons, flag)
    total = cart.get("total")
    ceiling = cons.get("max_amount")
    if total is not None and ceiling is not None:
        if Decimal(str(ceiling)) > Decimal(str(total)) * MAX_CEILING_MULTIPLE:
            flag("LOOSE_CEILING", "CWE-863",
                 f"max_amount {ceiling} >> cart total {total}; escalation headroom")
    _check_replay(sub, flag)
    _check_ttl(cons, flag)
    _check_presence(sub, cons, flag)


def _check_payment(sub, cons, flag):
    # A Payment Mandate detached from a reviewed Cart Mandate authorizes itself.
    if not sub.get("cart_ref"):
        flag("NO_CART_LINK", "CWE-345",
             "no cart_ref; payment is detached from any reviewed cart")
    # Payment method must be a tokenized/hashed reference, never a raw PAN.
    method = sub.get("payment_method_ref")
    raw = sub.get("payment_method") or sub.get("pan")
    if not method and raw and re.fullmatch(r"[\d \-]{12,23}", str(raw)):
        flag("UNHASHED_METHOD", "CWE-311",
             "payment_method looks like a raw card number, not a tokenized ref")
    elif not method and not raw:
        flag("NO_METHOD_REF", "CWE-345",
             "no payment_method_ref; nothing ties the charge to a vaulted instrument")
    _check_replay(sub, flag)
    _check_presence(sub, cons, flag)


def check(mandate):
    """Return a list of (code, cwe, message) findings for one mandate."""
    sub = mandate.get("credentialSubject", {})
    cons = sub.get("constraints", {})
    cart = sub.get("cart", {})
    findings = []

    def flag(code, cwe, message):
        findings.append((code, cwe, message))

    kind = mandate_type(mandate)
    if kind == "IntentMandate":
        _check_intent(sub, cons, flag)
    elif kind == "PaymentMandate":
        _check_payment(sub, cons, flag)
    else:
        _check_cart(sub, cons, cart, flag)
    return findings


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main(argv):
    paths = argv[1:] or sorted(glob.glob("samples/*.json"))
    if not paths:
        print("no mandates to check (pass JSON paths or populate samples/)")
        return 2

    clean = 0
    for path in paths:
        name = path.rsplit("/", 1)[-1].rsplit(".json", 1)[0]
        mandate = load(path)
        findings = check(mandate)
        kind = mandate_type(mandate)
        if not findings:
            clean += 1
            print(f"[PASS] {name}  <{kind}>")
        else:
            n = len(findings)
            print(f"[FAIL] {name}  <{kind}>  ({n} issue{'s' if n != 1 else ''})")
            for code, cwe, msg in findings:
                print(f"         - {code} ({cwe}): {msg}")

    print(f"\n{clean}/{len(paths)} mandates passed the counterfeit check.")
    print("\nBLIND SPOTS (static structure cannot decide these):")
    for b in BLIND_SPOTS:
        print(f"  - {b}")
    return 0 if clean == len(paths) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
