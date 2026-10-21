#!/usr/bin/env python3
"""Tests for the Canal Street mandate lint. stdlib unittest, no deps.

Run: python3 -m unittest -v
"""

import unittest

from mandate_lint import check, load


def codes(mandate):
    return {code for code, _cwe, _msg in check(mandate)}


class CleanMandate(unittest.TestCase):
    def test_tight_mandate_passes(self):
        self.assertEqual(codes(load("samples/clean-store-purchase.json")), set())


class HolidayWildcard(unittest.TestCase):
    def setUp(self):
        self.found = codes(load("samples/holiday-wildcard.json"))

    def test_catches_all_five_weaknesses(self):
        self.assertEqual(
            self.found,
            {"WILDCARD_SCOPE", "LOOSE_CEILING", "REPLAYABLE",
             "LONG_TTL", "UNVERIFIED_PRESENCE"},
        )

    def test_does_not_misflag_binding(self):
        # This mandate is bound and chained; those checks must not fire.
        self.assertNotIn("UNBOUND_AGENT", self.found)
        self.assertNotIn("NO_INTENT_CHAIN", self.found)


class UnboundSelfAuthorizing(unittest.TestCase):
    def setUp(self):
        self.found = codes(load("samples/unbound-self-authorizing.json"))

    def test_catches_unbound_and_unchained(self):
        self.assertIn("UNBOUND_AGENT", self.found)
        self.assertIn("NO_INTENT_CHAIN", self.found)
        self.assertIn("REPLAYABLE", self.found)
        self.assertIn("UNVERIFIED_PRESENCE", self.found)

    def test_scope_and_ceiling_are_tight(self):
        # allowed_merchants is specific and ceiling is close to the cart,
        # so these must not fire even on an otherwise weak mandate.
        self.assertNotIn("WILDCARD_SCOPE", self.found)
        self.assertNotIn("LOOSE_CEILING", self.found)


class EveryFindingCarriesACWE(unittest.TestCase):
    def test_cwe_present_on_each(self):
        for _code, cwe, _msg in check(load("samples/holiday-wildcard.json")):
            self.assertTrue(cwe.startswith("CWE-"), cwe)


if __name__ == "__main__":
    unittest.main(verbosity=2)
