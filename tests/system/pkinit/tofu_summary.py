#!/usr/bin/env python3
"""Render a GitHub Actions job-summary Markdown fragment for the PKINIT
KDC-CA TOFU system test.

Usage:
    tofu_summary.py MANIFEST.json >> "$GITHUB_STEP_SUMMARY"

Reads the same manifest.json produced by tofu_manifest.py that
tofu_report.py renders into the full HTML report -- see that file's
docstring for the manifest shape. This exists so the report is visible
directly on the Actions run's Summary tab, instead of only inside the
uploaded HTML artifact, which GitHub always zips and requires downloading
and unpacking to view. Trace logs are truncated to keep the summary
readable and within GitHub's per-step size limit; the HTML artifact still
carries them in full.
"""

import html
import json
import sys

MAX_TRACE_CHARS = 4000


def esc(value):
    return html.escape(str(value), quote=True)


def badge(passed):
    return "✅ PASS" if passed else "❌ FAIL"


def truncated_trace(text):
    text = text if text else "(empty)"
    if len(text) <= MAX_TRACE_CHARS:
        return text, False
    return text[-MAX_TRACE_CHARS:], True


def render_scenario(sc):
    name = sc.get("title") or sc.get("name") or "scenario"
    passed = bool(sc.get("passed"))
    expected = sc.get("expected", "?")
    outcome = sc.get("outcome", "?")
    decision = sc.get("broker_decision", "(unknown)")
    mode = sc.get("broker_mode", "?")
    fp = sc.get("ca_fingerprint") or "(none)"
    steps = sc.get("steps") or []
    traces = sc.get("traces") or {}

    lines = [f"### {esc(name)} — {badge(passed)}", ""]
    lines += [
        "| | | | |",
        "|---|---|---|---|",
        f"| **Expected** | {esc(expected)} | **Outcome** | {esc(outcome)} |",
        f"| **Broker mode** | {esc(mode)} | **Broker decision** | {esc(decision)} |",
        f"| **KDC CA SHA-256** | <code>{esc(fp)}</code> | | |",
        "",
    ]
    lines += [f"{i}. {s}" for i, s in enumerate(steps, 1)]
    lines.append("")

    for label, text in traces.items():
        shown, was_truncated = truncated_trace(text)
        lines.append("<details>")
        lines.append(f"<summary>{esc(label)}</summary>")
        lines.append("")
        lines.append(f"<pre>{esc(shown)}</pre>")
        if was_truncated:
            lines.append("")
            lines.append(
                f"_(showing the last {MAX_TRACE_CHARS} characters "
                "— download the `pkinit-tofu-report` artifact for "
                "the full trace)_"
            )
        lines.append("")
        lines.append("</details>")
        lines.append("")

    return "\n".join(lines)


def render(manifest):
    realm = manifest.get("realm", "(realm)")
    generated = manifest.get("generated", "")
    scenarios = manifest.get("scenarios") or []
    total = len(scenarios)
    passed = sum(1 for s in scenarios if s.get("passed"))
    overall_ok = total > 0 and passed == total
    overall = "ALL PASSED" if overall_ok else f"{passed}/{total} PASSED"
    overall_mark = "✅" if overall_ok else "❌"

    lines = [
        "## PKINIT KDC-CA Trust-On-First-Use",
        "",
        f"Realm `{esc(realm)}` &middot; generated {esc(generated)}",
        "",
        f"**{overall_mark} {overall}**",
        "",
    ]
    lines += [render_scenario(sc) for sc in scenarios]
    return "\n".join(lines) + "\n"


def main(argv):
    if len(argv) != 2:
        print(f"usage: {argv[0]} MANIFEST.json", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as f:
        manifest = json.load(f)
    sys.stdout.write(render(manifest))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
