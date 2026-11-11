"""Fetch verified contract source from Sourcify (free, no API key).

Sourcify is the open-source contract verification service; its public API
needs no key. Only GET requests are made, to repo.sourcify.dev.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

_SOURCIFY = ("https://sourcify.dev/server/v2/contract/{chain_id}/{address}"
             "?fields=sources,metadata")

# Chains Sourcify indexes that bounty hunters meet most often.
KNOWN_CHAINS = {
    1: "Ethereum",
    10: "Optimism",
    56: "BNB Smart Chain",
    137: "Polygon",
    8453: "Base",
    42161: "Arbitrum One",
    42220: "Celo",
    43114: "Avalanche",
    59144: "Linea",
    11155111: "Sepolia",
    11142220: "Celo Sepolia",
}


class SourcifyError(Exception):
    pass


def fetch_verified_source(chain_id: int, address: str) -> dict:
    """Return {contract_name, match, sources: {path: content}}.

    Raises SourcifyError with a plain message when the contract is not
    verified on Sourcify or the network call fails.
    """
    if not isinstance(chain_id, int) or chain_id <= 0:
        raise SourcifyError(f"Invalid chain_id: {chain_id!r} (expected a positive integer).")
    addr = address.strip()
    if not addr.startswith("0x") or len(addr) != 42:
        raise SourcifyError(f"Invalid address: {addr!r} (expected a 0x-prefixed 40-hex address).")
    url = _SOURCIFY.format(chain_id=chain_id, address=addr)
    req = urllib.request.Request(url, headers={"User-Agent": "audit-lens/0.1.0",
                                              "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            chain = KNOWN_CHAINS.get(chain_id, f"chain {chain_id}")
            raise SourcifyError(
                f"Contract {addr} is not verified on Sourcify for {chain}. "
                "Paste the source directly into audit_contract instead.")
        raise SourcifyError(f"Sourcify request failed (HTTP {exc.code}).")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SourcifyError(f"Could not reach Sourcify: {exc}.")

    std_json = data.get("stdJson") or {}
    sources = data.get("sources") or {}
    if not sources and std_json:
        sources = std_json.get("sources") or {}
    if not sources:
        raise SourcifyError(
            f"Sourcify has metadata for {addr} but no source files embedded.")
    match = data.get("creationMatch") or data.get("runtimeMatch") or "match"
    # Contract name: the first source whose path ends with the contract name,
    # else the largest source file.
    sol_sources = {p: s for p, s in sources.items() if p.endswith(".sol")}
    if not sol_sources:
        sol_sources = sources
    main_path = max(sol_sources, key=lambda p: len((sol_sources[p] or {}).get("content", "")))
    contract_name = main_path.rsplit("/", 1)[-1].replace(".sol", "")
    return {
        "contract_name": contract_name,
        "match": match,
        "sources": {p: (s or {}).get("content", "") for p, s in sol_sources.items()},
        "main_path": main_path,
    }


def main_source(result: dict, max_chars: int = 12000) -> str:
    """The main source file, truncated with a note when it is too long."""
    content = result["sources"].get(result["main_path"], "")
    if len(content) > max_chars:
        return (content[:max_chars]
                + f"\n\n[... truncated: {len(content) - max_chars} more characters "
                  f"in {result['main_path']} ...]")
    return content
