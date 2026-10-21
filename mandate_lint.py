#!/usr/bin/env python3
"""canal_street_lab: a counterfeit check for AP2-style agent payment mandates.

AP2 (Google's Agent Payments Protocol) wraps an agent's purchase in signed
"mandates": an Intent Mandate for the goal, a Cart Mandate for the exact
items and totals, a Payment Mandate for the transfer. A valid signature
proves the bytes were not altered. It does not prove the authorization was
scoped so it cannot be reused, escalated, or replayed past the one purchase
it was signed for.

This is a static lint for Cart Mandates. It reads structure and flags the
field-level weaknesses that let a signed mandate pass authorization and then
keep working. It is deliberately honest about what structure cannot decide;
see the BLIND_SPOTS constant and the README.

stdlib only. Usage:
    python3 mandate_lint.py samples/*.json
    python3 mandate_lint.py            # defaults to everything in samples/
"""

import glob
import json
import sys
from datetime import datetime, timezone
from decimal import Decimal

# A Cart Mandate is a one-shot authorization. These thresholds decide when a
# field has turned it into a standing, reusable, or escalatable credential.
MAX_TTL_HOURS = 24
MAX_CEILING_MULTIPLE = Decimal("1.5")
# Fixed "now" so the sample output is reproducible; swap for datetime.now(tz)
# when linting live mandates.
NOW = datetime(2026, 12, 20, 12, 0, 0, tzinfo=timezone.utc)

BLIND_SPOTS = [
    "signature validity: needs the issuer's key to confirm the proof is real",
    "intent authenticity: intent_ref is checked for presence, not that it "
    "chains to a genuinely user-signed Intent Mandate",
    "presence truth: presence_evidence is checked for existence, not that a "
    "human actually authorized at transaction time",
]


def check(mandate):
    """Return a list of (code, cwe, message) findings for one Cart Mandate."""
    sub = mandate.get("credentialSubject", {})
    cons = sub.get("constraints", {})
    cart = sub.get("cart", {})
    findings = []

    def flag(code, cwe, message):
        findings.append((code, cwe, message))

    # A mandate not bound to the authorized agent can be presented by any agent.
    if not sub.get("agent_id"):
        flag("UNBOUND_AGENT", "CWE-639",
             "no agent_id; any agent can present this mandate")

    # A cart with no link back to a signed Intent Mandate authorizes itself.
    if not sub.get("intent_ref"):
        flag("NO_INTENT_CHAIN", "CWE-345",
             "no intent_ref; cart authorizes itself")

    # Wildcard/empty merchant scope means the mandate is spendable anywhere.
    allowed = cons.get("allowed_merchants")
    if not allowed or "*" in allowed:
        flag("WILDCARD_SCOPE", "CWE-863",
             "allowed_merchants is empty or '*'; reusable at any merchant")

    # A ceiling far above the cart total is room to escalate the amount charged.
    total = cart.get("total")
    ceiling = cons.get("max_amount")
    if total is not None and ceiling is not None:
        if Decimal(str(ceiling)) > Decimal(str(total)) * MAX_CEILING_MULTIPLE:
            flag("LOOSE_CEILING", "CWE-863",
                 f"max_amount {ceiling} >> cart total {total}; escalation headroom")

    # No nonce means nothing stops the same mandate being submitted twice.
    if not sub.get("nonce"):
        flag("REPLAYABLE", "CWE-294",
             "no nonce; same mandate can be submitted repeatedly")

    # A long expiry turns a one-shot authorization into a multi-day bearer token.
    exp = cons.get("expiry")
    if exp:
        exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        ttl_hours = (exp_dt - NOW).total_seconds() / 3600
        if ttl_hours > MAX_TTL_HOURS:
            flag("LONG_TTL", "CWE-613",
                 f"expiry {ttl_hours:.0f}h out (> {MAX_TTL_HOURS}h); standing token")

    # human_present asserted with no attached evidence to verify it against.
    if cons.get("human_present") is True and not sub.get("presence_evidence"):
        flag("UNVERIFIED_PRESENCE", "CWE-287",
             "human_present=true with no presence_evidence to check")

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
        findings = check(load(path))
        if not findings:
            clean += 1
            print(f"[PASS] {name}")
        else:
            n = len(findings)
            print(f"[FAIL] {name}  ({n} issue{'s' if n != 1 else ''})")
            for code, cwe, msg in findings:
                print(f"         - {code} ({cwe}): {msg}")

    print(f"\n{clean}/{len(paths)} mandates passed the counterfeit check.")
    print("\nBLIND SPOTS (static structure cannot decide these):")
    for b in BLIND_SPOTS:
        print(f"  - {b}")
    # Non-zero exit if any mandate failed, so this can gate CI.
    return 0 if clean == len(paths) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
