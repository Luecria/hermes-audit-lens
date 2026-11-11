"""Render the audit-lens demo video from REAL captured tool output.

Frames are terminal snapshots (1280x720, DejaVu Sans Mono); each line
appears in turn, as if typed. ffmpeg stitches them into an MP4.
No synthetic output: every line below is copied from a real run.
"""

import os
import subprocess

from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 720
BG = (13, 17, 23)
FG = (230, 237, 243)
GREEN = (126, 231, 135)
BRIGHT_GREEN = (63, 185, 80)
RED = (255, 123, 114)
YELLOW = (210, 153, 34)
BLUE = (88, 166, 255)
GRAY = (139, 148, 158)

FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
TITLE_FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

OUT_DIR = "/tmp/audit-lens-video"
FRAMES = os.path.join(OUT_DIR, "frames")
os.makedirs(FRAMES, exist_ok=True)


def color_for(line: str):
    if line.startswith("$ "):
        return GREEN
    if line.startswith("[High]"):
        return RED
    if line.startswith("[Medium]"):
        return YELLOW
    if line.startswith("[Low]"):
        return BLUE
    if line.startswith("✓") or "Validation passed." in line or line.strip() == "OK":
        return BRIGHT_GREEN
    if line.startswith("Findings:") or line.startswith("audit-lens —"):
        return FG
    return (200, 208, 216)


# (lines, seconds-per-line, extra hold after segment)
SEGMENTS = [
    ([("TITLE", "audit-lens"),
      ("SUB", "Deterministic smart-contract security review for Hermes Agent"),
      ("SUB", "Hermes Agent Plugin Hackathon — November 2026")], 0, 4.0),
    (["$ hermes plugins validate",
      "✓ manifest — plugin.yaml parses",
      "✓ manifest fields — name, version, description present",
      "✓ requires_hermes — spec '>=0.21.0' parses",
      "✓ config schema — not declared",
      "✓ requires_env — all entries UPPER_SNAKE",
      "✓ oauth — not declared",
      "✓ loadable — entry: __init__.py",
      "✓ python dependencies — none declared",
      "✓ capability probe — register() ran in isolation",
      "✓ declared tools — matches registrations",
      "✓ declared hooks — matches registrations",
      "✓ declared middleware — matches registrations",
      "✓ built-in tool collisions — no collisions",
      "✓ security scan — safe",
      "✓ no core override — no runtime rebinds of Hermes core",
      "◇ Isolation — runs in the plugin host",
      "",
      "Validation passed."], 0.45, 1.2),
    (["$ hermes plugins doctor",
      "Plugin Doctor: /home/daytona/hermes-audit-lens",
      "  manifest: audit-lens 0.1.0 (standalone)",
      "  OK: runtime discovery, manifest parsing, import, and registration passed",
      "  registrations: 4 tool(s), 0 hook(s)"], 0.5, 1.0),
    (["$ hermes plugins list",
      "  audit-lens    enabled    0.1.0    Deterministic smart-contract review    user"], 0.6, 1.0),
    (["$ python3 demo/run_demo.py",
      "",
      "audit-lens — examples/Vault.sol",
      "Findings: 4 (High 2, Medium 1, Low 1)",
      "",
      "[High] TX_ORIGIN — tx.origin used for authorization (line 17)",
      '    require(tx.origin == msg.sender, "only EOA");',
      "    Fix: Use msg.sender for authorization.",
      "",
      "[High] REENTRANCY — State updated after an external call (line 20)",
      "    balances[msg.sender] -= amount;",
      "    Fix: Move state updates before the call, or add nonReentrant.",
      "",
      "[Medium] UNCHECKED_CALL — Return value of call is not checked (line 26)",
      '    to.call{value: amount}("");',
      "    Fix: Capture the return value and require() success.",
      "",
      "[Low] FLOATING_PRAGMA — Floating compiler pragma (^0.8.0) (line 2)",
      "    pragma solidity ^0.8.0;",
      "    Fix: Lock the pragma to one exact compiler version."], 0.55, 1.5),
    (["$ fetch_verified_source(chain 1, WETH 0xC02a…)",
      "Verified source for 0xC02a… on Ethereum (match: match)",
      "Contract: WETH9 (WETH9.sol)",
      "Source files: 1"], 0.6, 1.0),
    (["$ check_duplicate(\"Reentrancy in Vault.withdraw\")",
      "- SWC-107 Reentrancy — state updated after an external call (score 0.29)",
      "  The single most reported issue class in public audits.",
      "",
      "$ draft_finding(...)",
      "# Reentrancy in Vault.withdraw allows draining the vault",
      "Severity: High",
      "Target: Vault (examples/Vault.sol)"], 0.55, 1.2),
    (["$ python3 -m unittest discover -s tests",
      "Ran 16 tests in 0.007s",
      "",
      "OK"], 0.6, 1.0),
    ([("TITLE", "audit-lens"),
      ("SUB", "4 tools. 16 tests. 0 dependencies."),
      ("SUB", "github.com/Luecria/hermes-audit-lens")], 0, 5.0),
]


def draw_frame(lines, frame_no):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    if lines and isinstance(lines[0], tuple) and lines[0][0] == "TITLE":
        title_font = ImageFont.truetype(TITLE_FONT, 64)
        sub_font = ImageFont.truetype(FONT_PATH, 26)
        y = 250
        for kind, text in lines:
            f = title_font if kind == "TITLE" else sub_font
            color = GREEN if kind == "TITLE" else GRAY
            bbox = d.textbbox((0, 0), text, font=f)
            x = (W - (bbox[2] - bbox[0])) // 2
            d.text((x, y), text, font=f, fill=color)
            y += (bbox[3] - bbox[1]) + 28
    else:
        font = ImageFont.truetype(FONT_PATH, 21)
        lh = 30
        visible = lines[-21:]
        y = 30
        for line in visible:
            d.text((36, y), line, font=font, fill=color_for(line))
            y += lh
    path = os.path.join(FRAMES, f"f{frame_no:04d}.png")
    img.save(path)
    return path


def main():
    concat = []
    frame_no = 0
    total = 0.0
    for lines, per_line, hold in SEGMENTS:
        if lines and isinstance(lines[0], tuple):
            frame_no += 1
            path = draw_frame(lines, frame_no)
            concat.append((path, hold))
            total += hold
            continue
        shown: list[str] = []
        for line in lines:
            shown.append(line)
            frame_no += 1
            path = draw_frame(shown, frame_no)
            dur = per_line
            # Key findings get a longer look.
            if line.startswith("[High]") or line.startswith("[Medium]"):
                dur = 1.1
            concat.append((path, dur))
            total += dur
        if hold:
            concat.append((concat[-1][0], hold))
            total += hold
    with open(os.path.join(OUT_DIR, "concat.txt"), "w") as f:
        for path, dur in concat:
            f.write(f"file '{path}'\nduration {dur:.2f}\n")
        f.write(f"file '{concat[-1][0]}'\n")
    print(f"frames: {frame_no}, total duration: {total:.1f}s")
    subprocess.run([
        "ffmpeg", "-y", "-f", "concat", "-safe", "0",
        "-i", os.path.join(OUT_DIR, "concat.txt"),
        "-vf", "format=yuv420p",
        "-c:v", "libx264", "-r", "30",
        os.path.join(OUT_DIR, "audit-lens-demo.mp4"),
    ], check=True)
    print("wrote", os.path.join(OUT_DIR, "audit-lens-demo.mp4"))


if __name__ == "__main__":
    main()
