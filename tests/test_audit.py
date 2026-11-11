"""Tests for the audit-lens check engine (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit import audit_source, strip_comments  # noqa: E402
from known_issues import check_duplicate  # noqa: E402
from tools import handle_draft_finding  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLES = os.path.join(HERE, "..", "examples")


def _ids(findings):
    return {f.id for f in findings}


class TestStripComments(unittest.TestCase):
    def test_line_numbers_preserved(self):
        src = "a\n// comment\nb /* multi\nline */ c\n"
        stripped = strip_comments(src)
        self.assertEqual(stripped.count("\n"), src.count("\n"))
        self.assertNotIn("comment", stripped)
        self.assertNotIn("multi", stripped)


class TestVault(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(EXAMPLES, "Vault.sol")) as f:
            self.vault = f.read()
        with open(os.path.join(EXAMPLES, "SecureVault.sol")) as f:
            self.secure = f.read()

    def test_vault_has_reentrancy_tx_origin_unchecked(self):
        ids = _ids(audit_source(self.vault))
        self.assertIn("REENTRANCY", ids)
        self.assertIn("TX_ORIGIN", ids)
        self.assertIn("UNCHECKED_CALL", ids)

    def test_vault_floating_pragma(self):
        ids = _ids(audit_source(self.vault))
        self.assertIn("FLOATING_PRAGMA", ids)

    def test_secure_vault_clean_of_high_medium(self):
        findings = audit_source(self.secure)
        bad = [f for f in findings if f.severity in ("High", "Medium")]
        self.assertEqual(bad, [], [f.format() for f in bad])

    def test_reentrancy_line_is_state_write(self):
        findings = audit_source(self.vault)
        r = [f for f in findings if f.id == "REENTRANCY"]
        self.assertEqual(len(r), 1)
        self.assertIn("balances[msg.sender] -= amount", r[0].snippet)


class TestChecks(unittest.TestCase):
    def test_selfdestruct_unprotected(self):
        src = ("pragma solidity 0.8.24;\ncontract A {\n"
               "  function kill() external {\n    selfdestruct(payable(msg.sender));\n  }\n}")
        self.assertIn("SELFDESTRUCT", _ids(audit_source(src)))

    def test_selfdestruct_protected_is_clean(self):
        src = ("pragma solidity 0.8.24;\ncontract A {\n"
               "  address owner;\n"
               "  function kill() external onlyOwner {\n    selfdestruct(payable(owner));\n  }\n}")
        self.assertNotIn("SELFDESTRUCT", _ids(audit_source(src)))

    def test_delegatecall_variable_target(self):
        src = ("pragma solidity 0.8.24;\ncontract A {\n"
               "  function f(address t, bytes memory d) external {\n"
               "    (bool ok, ) = t.delegatecall(d);\n    require(ok);\n  }\n}")
        self.assertIn("DELEGATECALL", _ids(audit_source(src)))

    def test_checked_call_is_clean(self):
        src = ("pragma solidity 0.8.24;\ncontract A {\n"
               "  function f(address t) external {\n"
               "    (bool ok, ) = t.call(\"\");\n    require(ok);\n  }\n}")
        self.assertNotIn("UNCHECKED_CALL", _ids(audit_source(src)))

    def test_access_control_missing(self):
        src = ("pragma solidity 0.8.24;\ncontract A {\n"
               "  uint public fee;\n"
               "  function setFee(uint x) external {\n    fee = x;\n  }\n}")
        self.assertIn("ACCESS_CONTROL", _ids(audit_source(src)))

    def test_timestamp_in_require(self):
        src = ("pragma solidity 0.8.24;\ncontract A {\n"
               "  function f() external {\n"
               "    require(block.timestamp > 1000);\n  }\n}")
        self.assertIn("TIMESTAMP", _ids(audit_source(src)))

    def test_precision_loss(self):
        src = ("pragma solidity 0.8.24;\ncontract A {\n"
               "  function f(uint a, uint b, uint c) external pure returns (uint) {\n"
               "    return a / b * c;\n  }\n}")
        self.assertIn("PRECISION_LOSS", _ids(audit_source(src)))

    def test_transfer_send_flagged_low(self):
        src = ("pragma solidity 0.8.24;\ncontract A {\n"
               "  function f(address payable t) external {\n"
               "    t.transfer(1 ether);\n  }\n}")
        findings = audit_source(src)
        t = [f for f in findings if f.id == "TRANSFER_SEND"]
        self.assertEqual(len(t), 1)
        self.assertEqual(t[0].severity, "Low")


class TestDuplicateAndDraft(unittest.TestCase):
    def test_duplicate_matches_reentrancy(self):
        matches = check_duplicate(
            "Reentrancy in withdraw",
            "Ether is sent before the balance is updated, so a caller can re-enter withdraw.")
        self.assertTrue(matches)
        self.assertEqual(matches[0]["id"], "SWC-107")

    def test_duplicate_no_match_is_quiet(self):
        matches = check_duplicate(
            "Purple unicorn alignment",
            "The contract's aura is misaligned with the moon phase.")
        self.assertEqual(matches, [])

    def test_draft_has_all_sections(self):
        out = handle_draft_finding({
            "title": "Reentrancy in Vault.withdraw",
            "severity": "High",
            "description": "desc",
            "impact": "impact",
            "recommendation": "fix",
            "contract": "Vault",
            "evidence": "audit-lens: REENTRANCY line 17",
        })
        for section in ("# Reentrancy in Vault.withdraw", "Severity: High",
                        "Target: Vault", "## Description", "## Impact",
                        "## Recommendation", "## Evidence", "## Limits"):
            self.assertIn(section, out)


if __name__ == "__main__":
    unittest.main()
