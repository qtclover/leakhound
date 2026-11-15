#!/usr/bin/env python3
"""Generate assets/demo.svg, the animated terminal in the README.

The session below is real output, captured from a throwaway repository with
the pre-commit hook installed. Run this script again after changing it:

    python3 assets/make-demo.py
"""
from html import escape
from pathlib import Path

# (kind, segments); a segment is (text, style class).
SESSION = [
    ("cmd", "leakhound install-hook"),
    ("out", [("installed pre-commit hook at ./.git/hooks/pre-commit", "")]),
    ("gap", None),
    ("cmd", 'git commit -m "add deploy script"'),
    ("out", [("github-token", "red"), ("  GitHub token", "")]),
    ("out", [("  deploy.sh:3:11", "bold")]),
    ("out", [("  secret   ghp_************J6  ", ""), ("(entropy 5.07)", "dim")]),
    ("gap", None),
    ("out", [("scanned staged changes (0.0 MB of added lines) in 0.00s, 1 finding", "")]),
    ("gap", None),
    ("cmd", "git log --oneline"),
    ("out", [("d844e32 initial", "")]),
    ("out", [("# the commit with the token never happened", "dim")]),
]

WIDTH, PAD, TOP, LINE = 760, 22, 58, 22
CHAR = 8.43  # advance of one 14px monospace character
TYPE_SPEED = 0.045  # seconds per typed character
PAUSE_BEFORE_CMD, PAUSE_AFTER_CMD, OUT_STEP, HOLD = 0.9, 0.45, 0.07, 4.0


def main():
    # First pass: lay out the timeline.
    t, y, rows = 0.6, TOP, []
    for kind, body in SESSION:
        if kind == "gap":
            y += LINE // 2
            continue
        if kind == "cmd":
            t += PAUSE_BEFORE_CMD
            typed = len(body) * TYPE_SPEED
            rows.append((kind, body, y, t, t + typed))
            t += typed + PAUSE_AFTER_CMD
        else:
            rows.append((kind, body, y, t, t))
            t += OUT_STEP
        y += LINE
    total = t + HOLD
    height = y + PAD - 6

    css, body = [], []
    pct = lambda seconds: f"{100 * seconds / total:.2f}%"
    for i, (kind, content, y, start, end) in enumerate(rows):
        # Everything is hidden until its moment and cleared just before the loop restarts.
        css.append(
            f"@keyframes show{i}{{0%,{pct(start - 0.01)}{{opacity:0}}"
            f"{pct(start)},98%{{opacity:1}}100%{{opacity:0}}}}"
            f".l{i}{{opacity:0;animation:show{i} {total:.2f}s linear infinite}}"
        )
        if kind == "cmd":
            n = len(content)
            css.append(
                f"@keyframes type{i}{{0%,{pct(start)}{{width:0;animation-timing-function:steps({n},end)}}"
                f"{pct(end)},100%{{width:{n * CHAR:.1f}px}}}}"
                f".c{i}{{animation:type{i} {total:.2f}s linear infinite}}"
            )
            x = PAD + 2 * CHAR
            body.append(
                f'<g class="l{i}"><text x="{PAD}" y="{y}" class="green">$</text>'
                f'<clipPath id="clip{i}"><rect class="c{i}" x="{x:.1f}" y="{y - 16}" height="22" width="0"/></clipPath>'
                f'<text x="{x:.1f}" y="{y}" clip-path="url(#clip{i})">{escape(content)}</text></g>'
            )
        else:
            spans = "".join(
                f'<tspan class="{cls}">{escape(text)}</tspan>' if cls else escape(text)
                for text, cls in content
            )
            body.append(f'<text class="l{i}" x="{PAD}" y="{y}">{spans}</text>')

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {height}" width="{WIDTH}" role="img" aria-label="Terminal session: leakhound's pre-commit hook rejects a commit that contains a GitHub token">
<style>
text{{font:14px ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;fill:#d7dce5;white-space:pre}}
.red{{fill:#ff6b6b;font-weight:700}}.bold{{font-weight:700;fill:#fff}}.dim{{fill:#7d8799}}.green{{fill:#6bd68a}}
{"".join(css)}
@media (prefers-reduced-motion:reduce){{*{{animation:none!important;opacity:1!important}}rect[class^="c"]{{width:{WIDTH}px}}}}
</style>
<rect width="{WIDTH}" height="{height}" rx="10" fill="#14171d"/>
<rect width="{WIDTH}" height="34" rx="10" fill="#1e222b"/><rect y="24" width="{WIDTH}" height="10" fill="#1e222b"/>
<circle cx="20" cy="17" r="6" fill="#ff5f57"/><circle cx="40" cy="17" r="6" fill="#febc2e"/><circle cx="60" cy="17" r="6" fill="#28c840"/>
<g xml:space="preserve">
{chr(10).join(body)}
</g>
</svg>
"""
    out = Path(__file__).with_name("demo.svg")
    out.write_text(svg)
    print(f"wrote {out} ({len(svg)} bytes, {total:.1f}s loop)")


if __name__ == "__main__":
    main()
