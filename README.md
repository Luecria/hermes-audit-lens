# audit-lens

A Hermes Agent plugin for deterministic smart-contract security review.
It gives the agent real tools — not just a prompt — for the first pass of
a contract review: fetch verified source, run static checks, flag
likely-known issues, and draft a structured finding.

## Tools

| Tool | What it does |
| --- | --- |
| `audit_contract` | Runs pattern-based static checks over Solidity source (inline or a local `.sol` file). Returns findings with severity, line numbers and fixes. |
| `fetch_verified_source` | Pulls verified source from Sourcify by chain ID + address. Free, no API key. |
| `check_duplicate` | Matches a finding against a curated database of publicly known issue classes (SWC registry). A match is a triage signal, not a verdict. |
| `draft_finding` | Formats a structured finding report (title, severity, description, impact, recommendation, limits). |

Slash command: `/audit-lens` (`checks` lists the checks, `audit <path>` audits a file).

## Checks

reentrancy, tx.origin authorization, unchecked low-level call return,
unprotected selfdestruct, delegatecall to a non-constant target, sensitive
function without access control, transfer/send stipend, block.timestamp in
a condition, unbounded loop with an external call, floating pragma,
division-before-multiplication precision loss.

## Install

```
hermes plugins install Luecria/hermes-audit-lens
```

Requires Hermes >= 0.21.0. Standard library only — no dependencies, no
build step.

## Disclosure

- Network: one GET to `sourcify.dev` (v2 contract API) per
  `fetch_verified_source` call. Nothing else leaves the machine.
- Files: reads a local `.sol` file only when you pass its path to
  `audit_contract`. Nothing is written.
- No secrets, no credentials, no shell commands, no background processes.

## Limits (read this before trusting the output)

The checks are pattern-based. A finding is a lead to verify by hand, not
a proven exploit; a clean result does not mean the contract is safe. This
plugin does not replace manual review or a full analyzer (Slither,
Aderyn). Severity must follow the evidence — the plugin never inflates it.

## License

MIT
