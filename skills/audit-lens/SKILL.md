# audit-lens — smart-contract review methodology

Use this skill when reviewing a smart contract for security issues with the
audit-lens plugin. The plugin's checks are pattern-based: they find leads,
not exploits. Your job is to turn leads into verified findings — or kill
them.

## Workflow

1. **Get the source.** Prefer `fetch_verified_source` with the deployed
   chain ID and address (Sourcify, free, no key). If the contract is not
   verified, ask for the source or a local file path — never review from a
   screenshot or a decompiled listing.
2. **Run `audit_contract`.** Read every finding with its line number.
   Open the source at that line and verify the mechanism by hand:
   - Reentrancy: is the external call really before a state write, and is
     the called address attacker-controlled? A call to a fixed, trusted
     address is not reentrancy.
   - tx.origin: is it used for authorization, or only in an event/log?
   - Unchecked call: is the return value really ignored, or checked on
     another line?
   - Access control: does the function really lack a modifier, and does it
     move value or change privileged state?
3. **Kill false positives.** Say which findings you discarded and why.
   A check that fires on safe code is a bug in the check, not a finding.
4. **Check duplicates.** Run `check_duplicate` on each surviving finding.
   A match against a known public issue class means: check the program's
   audit history before spending more time. It is never, by itself, proof
   of a duplicate.
5. **Draft with `draft_finding`.** Severity follows the evidence:
   - High: funds or privileged access at stake with a realistic path.
   - Medium: real impact but gated by a condition you must name.
   - Low: hardening, or impact that needs an unrealistic precondition.
   Never inflate severity. State the honest limits in the report.

## Rules

- Verify deployed code, not the repo alone: the deployed bytecode may
  differ from HEAD.
- One finding per report. One mechanism, one impact, one fix.
- No exploit claims without a reproduction (local test, fork test, or a
  precise trace of the call sequence).
- Never report a finding you have not read in the source yourself.
