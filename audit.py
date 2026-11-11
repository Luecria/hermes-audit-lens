"""Deterministic Solidity static checks (standard library only).

Pattern-based, not a full analyzer: every check states exactly what it
looks for, and findings carry the matching source line so a human (or the
agent) can verify them. No network, no dependencies, no shell.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Finding:
    id: str
    title: str
    severity: str  # High | Medium | Low
    line: int
    snippet: str
    recommendation: str

    def format(self) -> str:
        return (
            f"[{self.severity}] {self.id} — {self.title} (line {self.line})\n"
            f"    {self.snippet}\n"
            f"    Fix: {self.recommendation}"
        )


# ---------------------------------------------------------------------------
# Source preparation: strip comments and string literals, preserving line
# numbers (every removed character becomes a space, newlines are kept).
# ---------------------------------------------------------------------------

def strip_comments(source: str) -> str:
    out: list[str] = []
    i, n = 0, len(source)
    while i < n:
        c = source[i]
        two = source[i:i + 2]
        if two == "//":
            while i < n and source[i] != "\n":
                out.append(" ")
                i += 1
        elif two == "/*":
            while i < n and source[i:i + 2] != "*/":
                out.append("\n" if source[i] == "\n" else " ")
                i += 1
            out.extend([" ", " "])
            i += 2
        elif c in ("\"", "'"):
            quote = c
            out.append(" ")
            i += 1
            while i < n and source[i] != quote:
                if source[i] == "\\":
                    out.append(" ")
                    i += 1
                    if i < n:
                        out.append("\n" if source[i] == "\n" else " ")
                        i += 1
                    continue
                out.append("\n" if source[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append(" ")
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def line_of(cleaned: str, pos: int) -> int:
    return cleaned.count("\n", 0, pos) + 1


def snippet_for(source: str, line_no: int) -> str:
    lines = source.split("\n")
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return ""


# ---------------------------------------------------------------------------
# Function splitting with brace matching.
# ---------------------------------------------------------------------------

@dataclass
class Function:
    name: str
    start_line: int
    body: str            # cleaned body text (without the signature)
    body_start_pos: int  # offset of the body in the cleaned source
    modifiers: str       # raw modifier text from the signature
    visibility: str


_FUNC_RE = re.compile(
    r"function\s+(\w+)\s*\([^)]*\)\s*"
    r"(?:external|public|internal|private)?\s*"
    r"([^{;]*)?\{",
    re.DOTALL,
)


def split_functions(cleaned: str) -> list[Function]:
    funcs: list[Function] = []
    for m in _FUNC_RE.finditer(cleaned):
        name = m.group(1)
        modifiers = (m.group(2) or "").strip()
        vis = "public" if "public" in modifiers else (
            "external" if "external" in modifiers else (
                "internal" if "internal" in modifiers else (
                    "private" if "private" in modifiers else "default")))
        body_start = m.end()
        depth = 1
        i = body_start
        while i < len(cleaned) and depth > 0:
            if cleaned[i] == "{":
                depth += 1
            elif cleaned[i] == "}":
                depth -= 1
            i += 1
        body = cleaned[body_start:i - 1]
        funcs.append(Function(
            name=name,
            start_line=line_of(cleaned, m.start()),
            body=body,
            body_start_pos=body_start,
            modifiers=modifiers,
            visibility=vis,
        ))
    return funcs


_STATE_VAR_RE = re.compile(
    r"^\s*(?:uint\d*|int\d*|address|bool|bytes\d*|string|mapping\s*\([^)]*\))"
    r"\s+(?:public\s+|private\s+|internal\s+|constant\s+|immutable\s+)*"
    r"(\w+)\s*(?:=|;)",
    re.MULTILINE,
)


def state_variables(cleaned: str) -> set[str]:
    """Names declared at contract level (outside any function body)."""
    funcs = split_functions(cleaned)
    spans = [(f.body_start_pos, f.body_start_pos + len(f.body)) for f in funcs]
    names: set[str] = set()
    for m in _STATE_VAR_RE.finditer(cleaned):
        pos = m.start()
        if any(a <= pos <= b for a, b in spans):
            continue
        names.add(m.group(1))
    return names


_ACCESS_MODIFIERS = ("onlyowner", "onlyrole", "onlyadmin", "requiresauth",
                     "onlyguardian", "onlymanager", "auth", "authorized")
_SENSITIVE_NAMES = ("mint", "burn", "pause", "unpause",
                    "setowner", "setfee", "upgrade", "initialize", "rescue",
                    "drain", "sweep", "setadmin")

_ASSIGN_RE = re.compile(r"(?<![=!<>+\-*/%])=(?!=)")
_COMPOUND_ASSIGN_RE = re.compile(r"(?:\+=|-=|\*=|/=|%=|\+\+|--|delete\s+)")


def _is_state_write(line: str, state_vars: set[str]) -> bool:
    if not (_ASSIGN_RE.search(line) or _COMPOUND_ASSIGN_RE.search(line)):
        return False
    for name in state_vars:
        if re.search(rf"\b{re.escape(name)}\b\s*(?:\[[^\]]*\])?\s*(?:\.[a-zA-Z_]\w*)?\s*(?:=|\+=|-=|\+\+|--)", line):
            return True
        if re.search(rf"\b{re.escape(name)}\b\s*\[[^\]]*\]\s*(?:=|\+=|-=)", line):
            return True
    return False


_EXTERNAL_CALL_RE = re.compile(
    r"\.\s*(?:call\s*\{[^}]*\}|call\s*\(|send\s*\(|transfer\s*\()")

_NONREENTRANT_RE = re.compile(r"\bnonReentrant\b", re.IGNORECASE)


def check_reentrancy(funcs: list[Function], state_vars: set[str],
                     cleaned: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    for fn in funcs:
        if _NONREENTRANT_RE.search(fn.modifiers):
            continue
        lines = fn.body.split("\n")
        call_line = None
        for idx, line in enumerate(lines):
            if _EXTERNAL_CALL_RE.search(line):
                call_line = idx
                break
        if call_line is None:
            continue
        for idx in range(call_line + 1, len(lines)):
            if _is_state_write(lines[idx], state_vars):
                abs_pos = fn.body_start_pos + sum(len(l) + 1 for l in lines[:idx])
                line_no = line_of(cleaned, abs_pos)
                out.append(Finding(
                    id="REENTRANCY",
                    title="State updated after an external call (checks-effects-interactions violated)",
                    severity="High",
                    line=line_no,
                    snippet=snippet_for(source, line_no),
                    recommendation="Move all state updates before the external call, or add a nonReentrant guard.",
                ))
                break
    return out


def check_tx_origin(cleaned: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    for m in re.finditer(r"\btx\.origin\b", cleaned):
        line_no = line_of(cleaned, m.start())
        out.append(Finding(
            id="TX_ORIGIN",
            title="tx.origin used for authorization",
            severity="High",
            line=line_no,
            snippet=snippet_for(source, line_no),
            recommendation="Use msg.sender for authorization; tx.origin can be abused by a phishing contract.",
        ))
    return out


_LOWLEVEL_RE = re.compile(r"\.\s*(call|delegatecall|staticcall)\s*(?:\(|\{)")
_CALL = r"\.\s*(call|delegatecall|staticcall)\s*(?:\(|\{)"


def check_unchecked_call(cleaned: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    for m in _LOWLEVEL_RE.finditer(cleaned):
        line_no = line_of(cleaned, m.start())
        line = snippet_for(source, line_no)
        stripped = line.strip()
        # Checked if the return value is used: assignment, require/if/assert.
        if re.search(r"^(?:\(?\s*bool[^;]*=\s*)?require\s*\(", stripped):
            continue
        if re.search(r"\brequire\s*\(.*" + _CALL, stripped):
            continue
        if re.search(r"\bif\s*\(.*" + _CALL, stripped):
            continue
        if re.search(r"=\s*[^;]*" + _CALL, stripped):
            continue
        if re.search(r"\bassert\s*\(.*" + _CALL, stripped):
            continue
        out.append(Finding(
            id="UNCHECKED_CALL",
            title=f"Return value of {m.group(1)} is not checked",
            severity="Medium",
            line=line_no,
            snippet=line,
            recommendation="Capture the return value and require() success, e.g. (bool ok, ) = target.call{value: x}(data); require(ok);",
        ))
    return out


def check_selfdestruct(funcs: list[Function], cleaned: str,
                       source: str) -> list[Finding]:
    out: list[Finding] = []
    for fn in funcs:
        if "selfdestruct" not in fn.body:
            continue
        mods = fn.modifiers.lower()
        if any(a in mods for a in _ACCESS_MODIFIERS):
            continue
        pos = fn.body_start_pos + fn.body.find("selfdestruct")
        line_no = line_of(cleaned, pos)
        out.append(Finding(
            id="SELFDESTRUCT",
            title="selfdestruct without access control",
            severity="High",
            line=line_no,
            snippet=snippet_for(source, line_no),
            recommendation="Restrict selfdestruct to the contract owner behind an access-control modifier.",
        ))
    return out


def check_delegatecall(funcs: list[Function], cleaned: str,
                       source: str) -> list[Finding]:
    out: list[Finding] = []
    for m in re.finditer(r"\.\s*delegatecall\s*\(", cleaned):
        arg_start = m.end()
        depth = 1
        i = arg_start
        while i < len(cleaned) and depth > 0:
            if cleaned[i] == "(":
                depth += 1
            elif cleaned[i] == ")":
                depth -= 1
            i += 1
        arg = cleaned[arg_start:i - 1].strip()
        # A constant / immutable target is a fixed implementation; anything
        # else (variable, parameter, mapping lookup) is user-influenced.
        if re.match(r"^(?:address\s*\()?0x[0-9a-fA-F]{40}\)?$", arg):
            continue
        if re.match(r"^[A-Z_][A-Z0-9_]*$", arg):
            continue
        line_no = line_of(cleaned, m.start())
        out.append(Finding(
            id="DELEGATECALL",
            title="delegatecall to a non-constant target address",
            severity="High",
            line=line_no,
            snippet=snippet_for(source, line_no),
            recommendation="delegatecall only to a fixed, audited implementation address; never to an address supplied by a caller or stored without access control.",
        ))
    return out


def check_access_control(funcs: list[Function], state_vars: set[str],
                         cleaned: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    for fn in funcs:
        if fn.visibility not in ("public", "external", "default"):
            continue
        if not any(fn.name.lower().startswith(s) for s in _SENSITIVE_NAMES):
            continue
        mods = fn.modifiers.lower()
        if any(a in mods for a in _ACCESS_MODIFIERS):
            continue
        if "onlyowner" in fn.body.lower()[:200] and "require" in fn.body.lower()[:200]:
            continue
        if not any(_is_state_write(l, state_vars) for l in fn.body.split("\n")):
            continue
        line_no = fn.start_line
        out.append(Finding(
            id="ACCESS_CONTROL",
            title=f"Sensitive function {fn.name}() has no access control",
            severity="Medium",
            line=line_no,
            snippet=snippet_for(source, line_no),
            recommendation="Add an access-control modifier (onlyOwner / a role) to this function.",
        ))
    return out


def check_transfer_send(cleaned: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    for m in re.finditer(r"\.\s*(transfer|send)\s*\(", cleaned):
        line_no = line_of(cleaned, m.start())
        out.append(Finding(
            id="TRANSFER_SEND",
            title=f"Ether sent with {m.group(1)} (fixed 2300-gas stipend)",
            severity="Low",
            line=line_no,
            snippet=snippet_for(source, line_no),
            recommendation="Prefer call{value:} with a checked return value; transfer/send can break if gas costs change.",
        ))
    return out


def check_timestamp(cleaned: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    for m in re.finditer(r"\bblock\.timestamp\b", cleaned):
        line_no = line_of(cleaned, m.start())
        line = snippet_for(source, line_no)
        if re.search(r"\b(require|if|while|assert)\b", line):
            out.append(Finding(
                id="TIMESTAMP",
                title="block.timestamp used in a condition",
                severity="Low",
                line=line_no,
                snippet=line,
                recommendation="Miners can shift block.timestamp by ~15 seconds; do not use it for randomness or strict deadlines.",
            ))
    return out


def check_unbounded_loop(funcs: list[Function], cleaned: str,
                         source: str) -> list[Finding]:
    out: list[Finding] = []
    for fn in funcs:
        for m in re.finditer(r"\bfor\s*\([^;]*;\s*[^;]*\.length\s*[;<]", fn.body):
            after = fn.body[m.start():m.start() + 400]
            if _EXTERNAL_CALL_RE.search(after):
                pos = fn.body_start_pos + m.start()
                line_no = line_of(cleaned, pos)
                out.append(Finding(
                    id="UNBOUNDED_LOOP",
                    title="Loop over a dynamic array with an external call inside",
                    severity="Low",
                    line=line_no,
                    snippet=snippet_for(source, line_no),
                    recommendation="Bound the loop or use a pull-payment pattern; an unbounded loop can run out of gas and brick the function.",
                ))
    return out


def check_pragma(cleaned: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    for m in re.finditer(r"pragma\s+solidity\s+([^;]+);", cleaned):
        spec = m.group(1).strip()
        if re.search(r"[\^><=]", spec) or " " in spec:
            line_no = line_of(cleaned, m.start())
            out.append(Finding(
                id="FLOATING_PRAGMA",
                title=f"Floating compiler pragma ({spec})",
                severity="Low",
                line=line_no,
                snippet=snippet_for(source, line_no),
                recommendation="Lock the pragma to one exact compiler version so the deployed bytecode matches the audited source.",
            ))
    return out


def check_precision(cleaned: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    for m in re.finditer(r"\b\w[\w\.\[\]]*\s*/\s*[^*/;]+\*\s*", cleaned):
        line_no = line_of(cleaned, m.start())
        out.append(Finding(
            id="PRECISION_LOSS",
            title="Division before multiplication (precision loss)",
            severity="Low",
            line=line_no,
            snippet=snippet_for(source, line_no),
            recommendation="Multiply before dividing, or scale by a fixed precision factor first.",
        ))
    return out


CHECKS = [
    ("reentrancy", check_reentrancy),
    ("tx_origin", check_tx_origin),
    ("unchecked_call", check_unchecked_call),
    ("selfdestruct", check_selfdestruct),
    ("delegatecall", check_delegatecall),
    ("access_control", check_access_control),
    ("transfer_send", check_transfer_send),
    ("timestamp", check_timestamp),
    ("unbounded_loop", check_unbounded_loop),
    ("pragma", check_pragma),
    ("precision", check_precision),
]

_SEVERITY_RANK = {"High": 0, "Medium": 1, "Low": 2}


def audit_source(source: str) -> list[Finding]:
    """Run every check over Solidity source; findings sorted by severity."""
    cleaned = strip_comments(source)
    funcs = split_functions(cleaned)
    state_vars = state_variables(cleaned)
    findings: list[Finding] = []
    findings += check_reentrancy(funcs, state_vars, cleaned, source)
    findings += check_tx_origin(cleaned, source)
    findings += check_unchecked_call(cleaned, source)
    findings += check_selfdestruct(funcs, cleaned, source)
    findings += check_delegatecall(funcs, cleaned, source)
    findings += check_access_control(funcs, state_vars, cleaned, source)
    findings += check_transfer_send(cleaned, source)
    findings += check_timestamp(cleaned, source)
    findings += check_unbounded_loop(funcs, cleaned, source)
    findings += check_pragma(cleaned, source)
    findings += check_precision(cleaned, source)
    findings.sort(key=lambda f: (_SEVERITY_RANK[f.severity], f.line))
    return findings


def format_report(findings: list[Finding], label: str) -> str:
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f.severity] += 1
    lines = [f"audit-lens — {label}",
             f"Findings: {len(findings)} "
             f"(High {counts['High']}, Medium {counts['Medium']}, Low {counts['Low']})"]
    if not findings:
        lines.append("No findings. These checks are pattern-based and do not "
                     "replace manual review or a full analyzer.")
    else:
        lines.append("")
        lines.extend(f.format() for f in findings)
        lines.append("")
        lines.append("Limits: pattern-based static checks. A finding is a "
                     "lead to verify by hand, not a proven exploit; a clean "
                     "result does not mean the contract is safe.")
    return "\n".join(lines)
