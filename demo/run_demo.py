"""Scripted demo driver for audit-lens: calls every tool with real inputs
and prints the real outputs. Used to produce the demo video when no LLM
is reachable from the sandbox; the outputs are 100% real tool output.
"""

import sys

sys.path.insert(0, "/home/daytona/hermes-audit-lens")

from tools import (  # noqa: E402
    handle_audit_contract,
    handle_fetch_verified_source,
    handle_check_duplicate,
    handle_draft_finding,
)

BANNER = "=" * 72


def section(title):
    print(f"\n{BANNER}\n{title}\n{BANNER}\n")


def main():
    section("1/4  audit_contract — examples/Vault.sol (3 planted bugs)")
    print(handle_audit_contract({"path": "/home/daytona/hermes-audit-lens/examples/Vault.sol"}))

    section("2/4  fetch_verified_source — WETH on Ethereum mainnet")
    try:
        print(handle_fetch_verified_source({
            "chain_id": 1,
            "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        })[:1500])
        print("\n[... source continues, 1500 chars shown ...]")
    except Exception as exc:  # noqa: BLE001 - demo driver, show the error
        print(f"fetch failed: {exc}")

    section("3/4  check_duplicate — the reentrancy finding")
    print(handle_check_duplicate({
        "title": "Reentrancy in Vault.withdraw",
        "description": "Ether is sent with call before the balance is updated, "
                       "so a caller can re-enter withdraw and drain the vault.",
    }))

    section("4/4  draft_finding — the reentrancy report")
    print(handle_draft_finding({
        "title": "Reentrancy in Vault.withdraw allows draining the vault",
        "severity": "High",
        "description": "Vault.withdraw sends ether with a low-level call (line 19) "
                       "before updating balances[msg.sender] (line 20).",
        "impact": "An attacker contract re-enters withdraw in the fallback and "
                  "drains the vault balance.",
        "recommendation": "Move the balance update before the external call "
                          "and add a nonReentrant guard.",
        "contract": "Vault (examples/Vault.sol)",
        "evidence": "audit-lens: REENTRANCY line 20; TX_ORIGIN line 17; "
                    "UNCHECKED_CALL line 26.",
    }))


if __name__ == "__main__":
    main()
