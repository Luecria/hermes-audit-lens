"""audit-lens plugin — deterministic smart-contract security review inside Hermes.

Tools: audit_contract, fetch_verified_source, check_duplicate, draft_finding.
Slash command: /audit-lens (checks | audit <path>).
Skill: audit-lens (review methodology, bundled under skills/).
"""

from __future__ import annotations

import logging
from pathlib import Path

try:  # package import (Hermes loads the plugin directory as a package)
    from . import tools as _tools
except ImportError:  # direct import (unit tests, standalone use)
    import tools as _tools

logger = logging.getLogger(__name__)

_TOOLS = (
    ("audit_contract", _tools.AUDIT_CONTRACT_SCHEMA, _tools.handle_audit_contract, "🔍"),
    ("fetch_verified_source", _tools.FETCH_VERIFIED_SOURCE_SCHEMA, _tools.handle_fetch_verified_source, "📥"),
    ("check_duplicate", _tools.CHECK_DUPLICATE_SCHEMA, _tools.handle_check_duplicate, "🔁"),
    ("draft_finding", _tools.DRAFT_FINDING_SCHEMA, _tools.handle_draft_finding, "📝"),
)

_HELP_TEXT = """
/audit-lens — deterministic smart-contract security review

Subcommands:
  checks                 List the static checks audit_contract runs
  audit <path>           Audit a local .sol file and print the findings

Tools (the agent calls these directly):
  audit_contract         Audit inline source or a local .sol file
  fetch_verified_source  Pull verified source from Sourcify (chain + address)
  check_duplicate        Match a finding against known public issue classes
  draft_finding          Format a structured finding report

All checks are pattern-based and standard-library only. A finding is a lead
to verify by hand, not a proven exploit.
"""


def _handle_slash(raw_args: str):
    argv = raw_args.strip().split()
    if not argv or argv[0] in {"help", "-h", "--help"}:
        return _HELP_TEXT
    if argv[0] == "checks":
        from .audit import CHECKS
        lines = ["audit-lens checks (pattern-based, stdlib only):"]
        for name, _fn in CHECKS:
            lines.append(f"  - {name}")
        return "\n".join(lines)
    if argv[0] == "audit":
        if len(argv) < 2:
            return "Usage: /audit-lens audit <path-to-.sol-file>"
        return _tools.handle_audit_contract({"path": argv[1]})
    return f"Unknown subcommand: {argv[0]}\n{_HELP_TEXT}"


def register(ctx) -> None:
    for name, schema, handler, emoji in _TOOLS:
        ctx.register_tool(name=name, toolset="audit_lens", schema=schema,
                          handler=handler, check_fn=_tools.check_requirements,
                          emoji=emoji)
    ctx.register_command("audit-lens", handler=_handle_slash,
                         description="Deterministic smart-contract security review.")
    # register_skill takes the SKILL.md file itself; resolve it against this
    # file so the path is correct whatever the working directory is.
    _skill_path = Path(__file__).resolve().parent / "skills" / "audit-lens" / "SKILL.md"
    ctx.register_skill("audit-lens", path=_skill_path,
                       description="Smart-contract review methodology: threat model, "
                       "invariants, severity calibration, duplicate check.")
