#!/usr/bin/env python3
"""Render a self-contained HTML report for the PKINIT KDC-CA TOFU system test.

Usage:
    tofu_report.py MANIFEST.json OUTPUT.html

The manifest is produced by tofu.sh and has the shape:

    {
      "generated": "<iso8601>",
      "realm": "PKINIT.TEST",
      "scenarios": [
        {
          "name": "happy-path",
          "title": "Trust on first use (happy path)",
          "expected": "success" | "failure",
          "outcome":  "success" | "failure",
          "passed":   true | false,
          "broker_mode": "approve" | "deny" | "seeded",
          "broker_decision": "Trusted" | "Denied" | "Unknown" | "(unknown)",
          "ca_fingerprint": "ab:cd:...",
          "steps": ["...", "..."],
          "traces": {"Client trace": "<text>", "KDC trace": "<text>",
                     "Broker log": "<text>"}
        }
      ]
    }

Missing fields degrade gracefully.
"""

import html
import json
import sys


def esc(value):
    return html.escape(str(value), quote=True)


def badge(passed):
    label = "PASS" if passed else "FAIL"
    cls = "pass" if passed else "fail"
    return f'<span class="badge {cls}">{label}</span>'


def render_scenario(sc):
    name = sc.get("title") or sc.get("name") or "scenario"
    passed = bool(sc.get("passed"))
    expected = sc.get("expected", "?")
    outcome = sc.get("outcome", "?")
    decision = sc.get("broker_decision", "(unknown)")
    mode = sc.get("broker_mode", "?")
    fp = sc.get("ca_fingerprint") or "(none)"

    steps = sc.get("steps") or []
    steps_html = "\n".join(
        f'<li><span class="step-n">{i + 1}</span>{esc(s)}</li>'
        for i, s in enumerate(steps)
    )

    traces = sc.get("traces") or {}
    traces_html = "\n".join(
        f"<details><summary>{esc(label)}</summary>"
        f"<pre>{esc(text) if text else '(empty)'}</pre></details>"
        for label, text in traces.items()
    )

    return f"""
    <section class="scenario {'ok' if passed else 'bad'}">
      <h2>{esc(name)} {badge(passed)}</h2>
      <table class="meta">
        <tr><th>Expected</th><td>{esc(expected)}</td>
            <th>Outcome</th><td>{esc(outcome)}</td></tr>
        <tr><th>Broker mode</th><td>{esc(mode)}</td>
            <th>Broker decision</th><td>{esc(decision)}</td></tr>
        <tr><th>KDC CA SHA-256</th><td colspan="3" class="mono">{esc(fp)}</td></tr>
      </table>
      <ol class="timeline">
        {steps_html}
      </ol>
      <div class="traces">
        {traces_html}
      </div>
    </section>
    """


def render(manifest):
    realm = manifest.get("realm", "(realm)")
    generated = manifest.get("generated", "")
    scenarios = manifest.get("scenarios") or []
    total = len(scenarios)
    passed = sum(1 for s in scenarios if s.get("passed"))
    overall_ok = total > 0 and passed == total
    overall = "ALL PASSED" if overall_ok else f"{passed}/{total} PASSED"

    body = "\n".join(render_scenario(s) for s in scenarios)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PKINIT KDC-CA TOFU report — {esc(realm)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; margin: 0; padding: 2rem;
         line-height: 1.5; max-width: 60rem; margin-inline: auto; }}
  h1 {{ font-size: 1.6rem; margin-bottom: 0.2rem; }}
  .sub {{ color: #6b7280; margin-top: 0; }}
  .overall {{ font-weight: 700; padding: 0.3rem 0.7rem; border-radius: 0.4rem;
             display: inline-block; margin: 0.5rem 0 1.5rem; }}
  .overall.ok {{ background: #dcfce7; color: #166534; }}
  .overall.bad {{ background: #fee2e2; color: #991b1b; }}
  .scenario {{ border: 1px solid #d1d5db; border-radius: 0.6rem;
              padding: 1rem 1.2rem; margin-bottom: 1.5rem; }}
  .scenario.ok {{ border-left: 6px solid #22c55e; }}
  .scenario.bad {{ border-left: 6px solid #ef4444; }}
  h2 {{ font-size: 1.15rem; display: flex; align-items: center; gap: 0.6rem; }}
  .badge {{ font-size: 0.75rem; font-weight: 700; padding: 0.1rem 0.5rem;
           border-radius: 0.3rem; }}
  .badge.pass {{ background: #22c55e; color: #052e16; }}
  .badge.fail {{ background: #ef4444; color: #450a0a; }}
  table.meta {{ border-collapse: collapse; margin: 0.5rem 0 1rem; width: 100%; }}
  table.meta th {{ text-align: left; color: #6b7280; font-weight: 600;
                  padding: 0.2rem 0.8rem 0.2rem 0; white-space: nowrap; }}
  table.meta td {{ padding: 0.2rem 1.2rem 0.2rem 0; }}
  .mono, pre {{ font-family: ui-monospace, monospace; }}
  .mono {{ word-break: break-all; }}
  ol.timeline {{ margin: 0.5rem 0; padding-left: 0; list-style: none; }}
  ol.timeline li {{ position: relative; padding: 0.25rem 0 0.25rem 2.2rem; }}
  .step-n {{ position: absolute; left: 0; display: inline-flex;
            width: 1.5rem; height: 1.5rem; align-items: center;
            justify-content: center; border-radius: 50%; background: #e5e7eb;
            color: #111827; font-size: 0.8rem; font-weight: 700; }}
  details {{ margin: 0.4rem 0; }}
  summary {{ cursor: pointer; font-weight: 600; }}
  pre {{ background: #1113; padding: 0.8rem; border-radius: 0.4rem;
        overflow-x: auto; font-size: 0.8rem; max-height: 22rem; }}
</style>
</head>
<body>
  <h1>PKINIT KDC-CA Trust-On-First-Use</h1>
  <p class="sub">Realm <span class="mono">{esc(realm)}</span>
     &middot; generated {esc(generated)}</p>
  <div class="overall {'ok' if overall_ok else 'bad'}">{esc(overall)}</div>
  {body}
</body>
</html>
"""


def main(argv):
    if len(argv) != 3:
        print(f"usage: {argv[0]} MANIFEST.json OUTPUT.html", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as f:
        manifest = json.load(f)
    output = render(manifest)
    with open(argv[2], "w", encoding="utf-8") as f:
        f.write(output)
    print(f"[tofu-report] wrote {argv[2]}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
