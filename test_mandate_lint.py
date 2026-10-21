#!/usr/bin/env python3
"""Tests for the Canal Street mandate lint. stdlib unittest, no deps.

Run: python3 -m unittest -v
"""

import unittest

from mandate_lint import check, load, mandate_type


def codes(mandate):
    return {code for code, _cwe, _msg in check(mandate)}


class TypeDetection(unittest.TestCase):
    def test_detects_each_type(self):
        self.assertEqual(mandate_type(load("samples/clean-store-purchase.json")), "CartMandate")
        self.assertEqual(mandate_type(load("samples/intent-scoped.json")), "IntentMandate")
        self.assertEqual(mandate_type(load("samples/payment-linked.json")), "PaymentMandate")


class CleanMandates(unittest.TestCase):
    def test_clean_cart_passes(self):
        self.assertEqual(codes(load("samples/clean-store-purchase.json")), set())

    def test_scoped_autonomous_intent_passes(self):
        # Autonomous (human-not-present) is fine when capped and merchant-scoped.
        self.assertEqual(codes(load("samples/intent-scoped.json")), set())

    def test_linked_payment_passes(self):
        self.assertEqual(codes(load("samples/payment-linked.json")), set())


class WeakCart(unittest.TestCase):
    def test_holiday_wildcard(self):
        self.assertEqual(
            codes(load("samples/holiday-wildcard.json")),
            {"WILDCARD_SCOPE", "LOOSE_CEILING", "REPLAYABLE",
             "LONG_TTL", "UNVERIFIED_PRESENCE"},
        )

    def test_unbound_self_authorizing(self):
        found = codes(load("samples/unbound-self-authorizing.json"))
        self.assertIn("UNBOUND_AGENT", found)
        self.assertIn("NO_INTENT_CHAIN", found)
        self.assertNotIn("WILDCARD_SCOPE", found)   # scope is specific
        self.assertNotIn("LOOSE_CEILING", found)     # ceiling is tight


class WeakIntent(unittest.TestCase):
    def test_autonomous_open_intent(self):
        self.assertEqual(
            codes(load("samples/intent-autonomous-open.json")),
            {"WILDCARD_SCOPE", "NO_SPEND_CAP", "AUTONOMOUS_BROAD",
             "REPLAYABLE", "LONG_TTL"},
        )


class WeakPayment(unittest.TestCase):
    def test_detached_payment(self):
        self.assertEqual(
            codes(load("samples/payment-detached.json")),
            {"NO_CART_LINK", "UNHASHED_METHOD", "REPLAYABLE", "UNVERIFIED_PRESENCE"},
        )


class EveryFindingCarriesACWE(unittest.TestCase):
    def test_cwe_present_on_each(self):
        for sample in ("holiday-wildcard", "intent-autonomous-open", "payment-detached"):
            for _code, cwe, _msg in check(load(f"samples/{sample}.json")):
                self.assertTrue(cwe.startswith("CWE-"), cwe)


if __name__ == "__main__":
    unittest.main(verbosity=2)
