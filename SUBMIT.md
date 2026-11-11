# audit-lens — submission pack (Hermes Agent Plugin Hackathon)

Deadline: **12 Nov 2026, 05:00 WIB** (11 Nov 17:00 EST).
Three requirements, all due by then:
1. Public repo + PR to the Hermes plugin catalog
2. Demo video (<90 s) posted on X tagging @NousResearch
3. Organiser form (Typeform FwJLvOln) with title, description, email, Discord, X link, PR link

## 1. Catalog entry (PR to NousResearch/hermes-agent)

File to add: `plugin-catalog/audit-lens.yaml`. Replace `<SHA>` with the full
40-character SHA of the release commit after pushing the repo.

```yaml
name: audit-lens
repo: https://github.com/Luecria/hermes-audit-lens
sha: <SHA>
description: >-
  Deterministic smart-contract security review inside Hermes: fetch verified
  source from Sourcify, run pattern-based static checks (reentrancy,
  tx.origin, unchecked calls, unprotected selfdestruct, delegatecall,
  access control), flag likely-known issues against a curated SWC database,
  and draft structured findings. Standard library only, no dependencies.
maintainer: Luecria
tier: community
category: tools
docs_url: https://github.com/Luecria/hermes-audit-lens#readme
version: "0.1.0"
requires_hermes: ">=0.21.0"
platforms: [linux, macos]
capabilities:
  provides_tools:
    - audit_contract
    - fetch_verified_source
    - check_duplicate
    - draft_finding
  provides_hooks: []
  provides_middleware: []
  requires_env: []
```

### PR description draft

Title: `Add audit-lens to the plugin catalog`

Body:
> audit-lens gives Hermes real smart-contract security tools: deterministic
> static checks over Solidity source, verified-source fetch from Sourcify,
> duplicate-risk flagging against a curated SWC database, and structured
> finding drafts. Standard library only, no dependencies, no build step.
>
> Evidence: `hermes plugins validate` passes 15/15 checks; `hermes plugins
> doctor` passes (4 tools registered); 16 unit tests pass; demo video
> (52 s) below.
>
> Disclosure (rule 13): network — one GET to `sourcify.dev` (v2 contract
> API) per `fetch_verified_source` call, nothing else leaves the machine. Files — reads a local `.sol` file only when its path is passed
> to `audit_contract`; nothing is written. No secrets, no credentials, no
> shell commands, no background processes, no self-updater, no binaries.

## 2. Demo video

File: `demo/audit-lens-demo.mp4` — 52 s, 1280x720, real terminal output only
(validate, doctor, list, audit of Vault.sol with 4 findings, Sourcify
fetch of WETH, duplicate check, finding draft, 16 tests).

Post on X with the video attached, tagging @NousResearch.

### X post draft (main, ~250 chars)

> audit-lens: a Hermes plugin that gives the agent real smart-contract security tools — deterministic checks, Sourcify fetch, duplicate flagging, finding drafts. 4 tools, 16 tests, 0 deps. Validate passed 15/15. @NousResearch

### Evidence reply (post as a reply to the main post)

> Demo (52 s) shows: validate 15/15, doctor OK, 4 tools registered. Vault.sol audit finds TX_ORIGIN + REENTRANCY (High), UNCHECKED_CALL (Medium), FLOATING_PRAGMA (Low); fixed SecureVault scores 0. Catalog PR: <PR-LINK>. Repo: github.com/Luecria/hermes-audit-lens

## 3. Organiser form (Typeform FwJLvOln)

- Title: audit-lens
- Description: Deterministic smart-contract security review plugin for Hermes Agent: 4 tools (audit_contract, fetch_verified_source, check_duplicate, draft_finding), 16 tests, 0 dependencies. Validated 15/15, doctor OK.
- Email: uplee4ever18@gmail.com
- Discord: (fill in the user's Discord handle)
- X link: (link to the X post above)
- PR link: (link to the catalog PR)

## Checklist

- [ ] Repo public at github.com/Luecria/hermes-audit-lens (push from ~/workspace/hermes-audit-lens)
- [ ] Release commit SHA recorded, catalog YAML filled in
- [ ] PR opened to NousResearch/hermes-agent, mergeable
- [ ] Video posted on X tagging @NousResearch (under 90 s — it is 52 s)
- [ ] Evidence reply posted under the X post
- [ ] Typeform submitted with both links
