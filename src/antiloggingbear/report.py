# Anti-Logging Bear by Priest

from __future__ import annotations

import datetime
import html
import json

from . import APP_NAME, __version__
from .engine.findings import ScanReport, Severity, Verdict

_SEVERITY_MARK = {
    Severity.CRITICAL: "!!",
    Severity.HIGH: "! ",
    Severity.MEDIUM: "~ ",
    Severity.LOW: "- ",
    Severity.INFO: "  ",
}


def plain_reasons(report: ScanReport, limit: int = 5) -> list[tuple[Severity, str]]:
    reasons: list[tuple[Severity, str]] = []
    for f in report.ranked():
        if f.severity < Severity.MEDIUM and report.verdict is not Verdict.CLEAN:
            break
        if f.severity < Severity.LOW:
            break
        line = f.title if not f.path else f"{f.path}: {f.title}"
        if all(line != existing for _sev, existing in reasons):
            reasons.append((f.severity, line))
        if len(reasons) >= limit:
            break
    return reasons


def to_text(report: ScanReport, verbose: bool = False) -> str:
    lines = [
        f"{APP_NAME} {__version__}",
        f"Target:  {report.target}",
        f"Verdict: {report.verdict.headline.upper()}",
        f"Checked {len(report.files)} file(s) in {report.duration:.1f}s",
        "",
    ]
    shown = [f for f in report.ranked() if verbose or f.severity >= Severity.LOW]
    if shown:
        lines.append("Findings:")
        for f in shown:
            lines.append(f"  {_SEVERITY_MARK[f.severity]} [{f.severity.label}] {f.title}")
            if f.path:
                lines.append(f"       file: {f.path}")
            if verbose and f.detail:
                lines.append(f"       {f.detail}")
            for ioc in f.indicators[:5]:
                lines.append(f"       -> {ioc}")
    else:
        lines.append("Nothing worth mentioning.")
    lines.append("")
    lines.append("Engines:")
    for name, status in report.engines.items():
        lines.append(f"  {name}: {status}")
    return "\n".join(lines)


def to_json(report: ScanReport) -> str:
    payload = report.to_dict()
    payload["scanner"] = f"{APP_NAME} {__version__}"
    payload["scanned_at"] = datetime.datetime.now().isoformat(timespec="seconds")
    return json.dumps(payload, indent=2)


_VERDICT_COLOURS = {
    Verdict.CLEAN: ("#2f6b3a", "#e6f2e3"),
    Verdict.SUSPICIOUS: ("#8a5a00", "#fbefd5"),
    Verdict.DANGEROUS: ("#a3241c", "#f9e1de"),
}


def to_html(report: ScanReport) -> str:
    fg, bg = _VERDICT_COLOURS[report.verdict]
    esc = html.escape
    rows = []
    for f in report.ranked():
        iocs = "".join(f"<div class='ioc'>{esc(i)}</div>" for i in f.indicators[:10])
        rows.append(
            "<tr class='sev-{sev}'><td>{label}</td><td>{path}</td><td><strong>{title}</strong>"
            "<div class='detail'>{detail}</div>{iocs}</td></tr>".format(
                sev=f.severity.name.lower(), label=f.severity.label, path=esc(f.path or "-"),
                title=esc(f.title), detail=esc(f.detail), iocs=iocs))
    files = "".join(
        f"<tr><td>{esc(r.path)}</td><td>{esc(r.kind)}</td><td>{r.size:,}</td><td class='hash'>{r.sha256}</td></tr>" for r in report.files)
    engines = "".join(f"<li><strong>{esc(k)}</strong>: {esc(v)}</li>" for k, v in report.engines.items())
    return _HTML_TEMPLATE.format(
        title=esc(APP_NAME), version=esc(__version__), target=esc(report.target),
        when=datetime.datetime.now().strftime("%d %b %Y, %H:%M"), fg=fg, bg=bg,
        verdict=esc(report.verdict.headline), count=len(report.files),
        findings="".join(rows) or "<tr><td colspan='3'>No findings.</td></tr>",
        files=files, engines=engines)


_HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} report</title>
<style>
:root {{ --bark:#5b3a1e; --forest:#24492e; --cream:#fbf6ea; --ink:#2a2118; }}
body {{ margin:0; background:var(--cream); color:var(--ink); font:15px/1.5 "Segoe UI",Helvetica,Arial,sans-serif; }}
header {{ background:var(--forest); color:#fff; padding:20px 24px; }}
header h1 {{ margin:0; font-size:22px; }} header p {{ margin:4px 0 0; opacity:.85; }}
main {{ max-width:1000px; margin:0 auto; padding:20px 16px 40px; }}
.verdict {{ background:{bg}; color:{fg}; border-left:8px solid {fg}; padding:16px 20px; border-radius:6px; font-size:20px; font-weight:700; }}
.meta {{ color:#6b5a48; margin:8px 0 24px; overflow-wrap:anywhere; }}
table {{ width:100%; border-collapse:collapse; margin-bottom:28px; background:#fff; }}
th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #eadfcb; vertical-align:top; overflow-wrap:anywhere; }}
th {{ background:#efe5d2; color:var(--bark); }}
.detail {{ color:#6b5a48; font-size:13px; }} .ioc {{ font-family:Consolas,monospace; font-size:12px; color:#7a2d18; }}
.hash {{ font-family:Consolas,monospace; font-size:12px; }}
.sev-critical td:first-child {{ color:#a3241c; font-weight:700; }} .sev-high td:first-child {{ color:#b4471a; font-weight:700; }}
.sev-medium td:first-child {{ color:#8a5a00; }}
</style></head><body>
<header><h1>{title}</h1><p>Scan report &middot; {when} &middot; v{version}</p></header>
<main>
<div class="verdict">{verdict}</div>
<p class="meta">{target} &middot; {count} file(s) checked without unzipping</p>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>File</th><th>What Barry found</th></tr>{findings}</table>
<h2>Files</h2>
<table><tr><th>File</th><th>Type</th><th>Bytes</th><th>SHA-256</th></tr>{files}</table>
<h2>Engines</h2><ul>{engines}</ul>
<p class="meta">Barry checks files without running or unzipping them. No scanner can promise a file is safe -
"No threats found" means nothing suspicious was spotted.</p>
</main></body></html>
"""
