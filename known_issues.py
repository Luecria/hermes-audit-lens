"""Small curated database of publicly known smart-contract issue classes.

Used by check_duplicate to flag when a finding matches a pattern that has
already been reported many times in public audits and bug bounties. This is
a triage signal, not a verdict: a match means "check the program's audit
history before you spend time on this", never "this is a duplicate".
"""

from __future__ import annotations

KNOWN_ISSUES = [
    {
        "id": "SWC-107",
        "title": "Reentrancy — state updated after an external call",
        "keywords": {"reentrancy", "reentrant", "external", "call", "withdraw",
                     "state", "checks-effects-interactions", "recursive"},
        "note": "The single most reported issue class in public audits. Any program whose code has been audited almost certainly has this in its known-issues list.",
    },
    {
        "id": "SWC-115",
        "title": "Authorization through tx.origin",
        "keywords": {"tx.origin", "txorigin", "origin", "authorization", "auth",
                     "phishing"},
        "note": "Documented as an anti-pattern in every major audit guide since 2018.",
    },
    {
        "id": "SWC-104",
        "title": "Unchecked return value of a low-level call",
        "keywords": {"unchecked", "call", "return", "low-level", "delegatecall",
                     "success", "ignored"},
        "note": "Common in older codebases; most audited projects already check every call return.",
    },
    {
        "id": "SWC-112",
        "title": "Delegatecall to an untrusted callee",
        "keywords": {"delegatecall", "delegate", "callee", "proxy", "implementation",
                     "untrusted"},
        "note": "Proxy/delegatecall issues are heavily covered in audit reports; check whether the target is fixed and audited.",
    },
    {
        "id": "SWC-105",
        "title": "Unprotected Ether withdrawal",
        "keywords": {"withdraw", "withdrawal", "unprotected", "ether", "drain",
                     "access", "owner"},
        "note": "Missing access control on withdrawal is a standard audit checklist item.",
    },
    {
        "id": "SWC-103",
        "title": "Floating pragma",
        "keywords": {"pragma", "floating", "compiler", "version", "locked"},
        "note": "Almost always informational in modern programs; rarely bounty-eligible on its own.",
    },
    {
        "id": "SWC-116",
        "title": "Block values as a proxy for time",
        "keywords": {"timestamp", "block.timestamp", "time", "deadline",
                     "randomness", "miner"},
        "note": "Timestamp dependence is a textbook finding; only reportable when the impact is concrete (funds or access at stake).",
    },
    {
        "id": "SWC-101",
        "title": "Integer overflow and underflow",
        "keywords": {"overflow", "underflow", "integer", "arithmetic",
                     "unchecked", "solidity", "0.8"},
        "note": "Solidity 0.8+ checks arithmetic by default; only `unchecked` blocks or old compilers are in scope.",
    },
    {
        "id": "SWC-113",
        "title": "DoS with failed call",
        "keywords": {"dos", "denial", "failed", "call", "revert", "loop",
                     "unbounded", "gas"},
        "note": "Loop + external call combinations are a known DoS pattern; check whether the loop is actually reachable with attacker-controlled length.",
    },
    {
        "id": "SWC-114",
        "title": "Transaction order dependence",
        "keywords": {"frontrunning", "front-running", "ordering", "mev",
                     "race", "sandwich"},
        "note": "Ordering issues need a concrete, profitable ordering to be more than informational.",
    },
    {
        "id": "SWC-106",
        "title": "Unprotected selfdestruct instruction",
        "keywords": {"selfdestruct", "suicide", "destruct", "destroy",
                     "unprotected"},
        "note": "selfdestruct is deprecated in newer Solidity but still appears in older deployed contracts.",
    },
    {
        "id": "SWC-123",
        "title": "Requirement violation (missing input validation)",
        "keywords": {"validation", "zero", "address", "input", "require",
                     "check"},
        "note": "Missing zero-address / bounds checks are common low-severity findings; programs often accept them as hardening at most.",
    },
]


def _tokens(text: str) -> set[str]:
    import re
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def check_duplicate(title: str, description: str, top_n: int = 3) -> list[dict]:
    """Rank known-issue classes by keyword overlap with the finding.

    Returns up to top_n entries with a 0..1 score; entries below 0.15 are
    dropped as noise.
    """
    hay = _tokens(title + " " + description)
    scored: list[tuple[float, dict]] = []
    for entry in KNOWN_ISSUES:
        kw = entry["keywords"]
        overlap = len(hay & kw)
        if overlap == 0:
            continue
        score = overlap / max(len(kw), len(hay))
        # Boost exact title-word matches.
        title_hits = len(_tokens(entry["title"]) & hay)
        score += 0.05 * title_hits
        scored.append((min(score, 1.0), entry))
    scored.sort(key=lambda x: -x[0])
    return [{"score": round(s, 2), **e} for s, e in scored[:top_n] if s >= 0.15]
