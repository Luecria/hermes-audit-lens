"""Agent-facing tools for the audit-lens plugin.

  audit_contract       — run deterministic checks over Solidity source
  fetch_verified_source — pull verified source from Sourcify by chain + address
  check_duplicate      — match a finding against known public issue classes
  draft_finding        — format a structured, submittable finding report
"""

from __future__ import annotations

import os
from typing import Any

try:  # package import (Hermes loads the plugin directory as a package)
    from . import audit as audit_mod
    from . import known_issues as ki
    from . import sourcify as sf
except ImportError:  # direct import (unit tests, standalone use)
    import audit as audit_mod
    import known_issues as ki
    import sourcify as sf


def check_requirements() -> bool:
    """Standard library only — always available."""
    return True


def _str(description: str) -> dict[str, Any]:
    return {"type": "string", "description": description}


def _int(description: str) -> dict[str, Any]:
    return {"type": "integer", "description": description}


def _schema(name: str, description: str, properties: dict[str, Any],
            required=None) -> dict[str, Any]:
    params: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        params["required"] = required
    params["additionalProperties"] = False
    return {"name": name, "description": description, "parameters": params}


AUDIT_CONTRACT_SCHEMA = _schema(
    "audit_contract",
    "Run deterministic static security checks over Solidity source and return "
    "structured findings with severity, line numbers and fixes. Give either "
    "`source` (inline Solidity) or `path` (a local .sol file). Pattern-based: "
    "findings are leads to verify by hand, and a clean result does not mean "
    "the contract is safe.",
    {"source": _str("Inline Solidity source code to audit. Use this or `path`."),
     "path": _str("Local path to a .sol file to audit. Use this or `source`.")},
    required=[])

FETCH_VERIFIED_SOURCE_SCHEMA = _schema(
    "fetch_verified_source",
    "Fetch the verified source of a deployed contract from Sourcify (free, "
    "no API key) by chain ID and address. Returns the contract name and the "
    "main source file, ready to pass into audit_contract.",
    {"chain_id": _int("EVM chain ID, e.g. 1 Ethereum, 42161 Arbitrum One, 8453 Base, 56 BNB Smart Chain."),
     "address": _str("Deployed contract address, 0x-prefixed.")},
    required=["chain_id", "address"])

CHECK_DUPLICATE_SCHEMA = _schema(
    "check_duplicate",
    "Match a finding title and description against a curated database of "
    "publicly known smart-contract issue classes (SWC registry). A match is "
    "a triage signal — check the program's audit history before reporting — "
    "never a verdict that the finding is a duplicate.",
    {"title": _str("One-line title of the finding."),
     "description": _str("A few sentences describing the mechanism and impact.")},
    required=["title", "description"])

DRAFT_FINDING_SCHEMA = _schema(
    "draft_finding",
    "Format a structured finding report from the audit output: title, "
    "severity, description, impact, recommendation, and the honest limits "
    "of the evidence. Use after audit_contract (and check_duplicate) so the "
    "report states what was actually proven.",
    {"title": _str("One-line title of the finding."),
     "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Informational"],
                  "description": "Severity. Do not inflate: use the severity the evidence supports."},
     "description": _str("What the bug is and where it lives (contract, function, line)."),
     "impact": _str("Concrete impact if exploited, with the conditions that must hold."),
     "recommendation": _str("The fix, as concretely as possible."),
     "contract": _str("Optional: contract name or address the finding applies to."),
     "evidence": _str("Optional: what was actually observed (tool output, test result), not assumed.")},
    required=["title", "severity", "description", "impact", "recommendation"])


def handle_audit_contract(args: dict[str, Any], **_kw) -> str:
    source = args.get("source") or ""
    path = args.get("path") or ""
    if path and not source:
        if not os.path.isfile(path):
            return f"audit-lens: no such file: {path}"
        if not path.endswith(".sol"):
            return f"audit-lens: expected a .sol file, got: {path}"
        try:
            with open(path, encoding="utf-8") as f:
                source = f.read()
        except OSError as exc:
            return f"audit-lens: could not read {path}: {exc}"
        label = path
    elif source:
        label = "inline source"
    else:
        return ("audit-lens: give `source` (inline Solidity) or `path` "
                "(a local .sol file).")
    if len(source) > 200_000:
        return ("audit-lens: source too large for a single audit "
                f"({len(source)} chars, max 200000). Split it per contract.")
    findings = audit_mod.audit_source(source)
    return audit_mod.format_report(findings, label)


def handle_fetch_verified_source(args: dict[str, Any], **_kw) -> str:
    chain_id = args.get("chain_id")
    address = args.get("address") or ""
    try:
        result = sf.fetch_verified_source(chain_id, address)
    except sf.SourcifyError as exc:
        return f"audit-lens: {exc}"
    chain = sf.KNOWN_CHAINS.get(chain_id, f"chain {chain_id}")
    out = [f"Verified source for {address} on {chain} "
           f"(match: {result['match']})",
           f"Contract: {result['contract_name']} "
           f"({result['main_path']})",
           f"Source files: {len(result['sources'])}",
           "",
           sf.main_source(result)]
    return "\n".join(out)


def handle_check_duplicate(args: dict[str, Any], **_kw) -> str:
    title = args.get("title") or ""
    description = args.get("description") or ""
    if not title and not description:
        return "audit-lens: give a `title` and a `description` to match."
    matches = ki.check_duplicate(title, description)
    if not matches:
        return ("audit-lens: no strong match against the known-issue database. "
                "That says nothing about duplicates in a specific program's "
                "private audit history — check that separately.")
    lines = ["audit-lens: possible matches against publicly known issue classes —",
             "a match is a reason to check the program's audit history, not a verdict."]
    for m in matches:
        lines.append(f"\n- {m['id']} {m['title']} (score {m['score']})")
        lines.append(f"  {m['note']}")
    return "\n".join(lines)


def handle_draft_finding(args: dict[str, Any], **_kw) -> str:
    title = args.get("title") or ""
    severity = args.get("severity") or ""
    description = args.get("description") or ""
    impact = args.get("impact") or ""
    recommendation = args.get("recommendation") or ""
    contract = args.get("contract") or ""
    evidence = args.get("evidence") or ""
    lines = [f"# {title}", "", f"Severity: {severity}"]
    if contract:
        lines.append(f"Target: {contract}")
    lines += ["", "## Description", description,
              "", "## Impact", impact,
              "", "## Recommendation", recommendation]
    if evidence:
        lines += ["", "## Evidence", evidence]
    lines += ["", "## Limits",
              "Severity is set from the evidence above. Pattern-based checks "
              "and a single review pass do not prove exploitability; verify "
              "the claim by hand (or with a PoC) before submitting."]
    return "\n".join(lines)
