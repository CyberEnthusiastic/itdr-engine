"""HTML report generator for ITDR Engine."""
import os
from html import escape


def generate_html(summary, alerts, output_path):
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    sev_color = {"CRITICAL": "#ff3b30", "HIGH": "#ff9500", "MEDIUM": "#ffcc00", "LOW": "#34c759"}

    rows = []
    for i, a in enumerate(sorted(alerts, key=lambda x: -x.risk_score)):
        sc = sev_color.get(a.severity, "#888")
        ev_html = "".join(f'<div class="ev">{escape(e)}</div>' for e in a.evidence[:5])
        rows.append(f"""
        <div class="alert" onclick="toggle({i})">
          <div class="ahead">
            <span class="sv" style="background:{sc}">{a.severity}</span>
            <span class="aname">{escape(a.detection_name)}</span>
            <span class="auser">{escape(a.user.split(',')[0])}</span>
            <span class="mitre">{escape(a.mitre_technique)}</span>
            <span class="risk">risk {a.risk_score}</span>
          </div>
          <div class="abody" id="ab-{i}">
            <div class="r"><b>User:</b> {escape(a.user)}</div>
            <div class="r"><b>Time:</b> {a.timestamp}</div>
            <div class="r"><b>MITRE:</b> {escape(a.mitre_tactic)} / {escape(a.mitre_technique)}</div>
            <div class="r"><b>Detail:</b> {escape(a.detail)}</div>
            <div class="r"><b>Evidence:</b></div>{ev_html}
            <div class="action"><b>Recommended:</b> {escape(a.recommended_action)}</div>
          </div>
        </div>""")

    risk_avg = summary.get("risk_score_avg", 0)
    risk_color = "#ff3b30" if risk_avg >= 80 else "#ff9500" if risk_avg >= 50 else "#34c759"

    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>ITDR Report</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0f1a;color:#cbd5e1;margin:0;padding:24px;max-width:1200px;margin:auto}}
h1{{color:#f87171;margin:0 0 4px;font-size:26px}}
.sub{{color:#64748b;font-size:13px;margin-bottom:20px}}
.hero{{background:#0f172a;border:1px solid #1e293b;border-radius:14px;padding:24px;margin-bottom:20px;display:flex;gap:20px;align-items:center;flex-wrap:wrap}}
.big{{font-size:48px;font-weight:900;line-height:1}}.bigl{{font-size:11px;color:#64748b;text-transform:uppercase}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;flex:1}}
.s{{background:#020617;border:1px solid #1e293b;border-radius:10px;padding:12px}}
.s .n{{font-size:22px;font-weight:800}}.s .l{{font-size:10px;color:#64748b;text-transform:uppercase}}
.alert{{background:#0f172a;border:1px solid #1e293b;border-radius:10px;margin-bottom:10px;overflow:hidden}}
.ahead{{display:flex;align-items:center;gap:12px;padding:14px 18px;cursor:pointer}}
.ahead:hover{{background:#131e35}}
.sv{{color:#000;font-weight:800;font-size:10px;padding:3px 10px;border-radius:10px;min-width:60px;text-align:center}}
.aname{{flex:1;color:#e2e8f0;font-weight:600;font-size:13px}}
.auser{{color:#60a5fa;font-size:11px;min-width:140px}}
.mitre{{color:#a78bfa;font-size:10px;font-family:monospace;min-width:100px}}
.risk{{color:#94a3b8;font-size:11px}}
.abody{{display:none;padding:14px 18px;border-top:1px solid #1e293b}}
.abody.open{{display:block}}
.r{{margin:6px 0;font-size:12px}}
.ev{{background:#020617;border-left:3px solid #475569;padding:6px 12px;font-size:11px;color:#94a3b8;margin:4px 0;border-radius:3px;font-family:monospace}}
.action{{background:#020617;border-left:3px solid #ff3b30;padding:10px 14px;margin-top:10px;border-radius:4px;font-size:12px;color:#f87171}}
.footer{{margin-top:30px;color:#334155;font-size:11px;text-align:center}}
</style></head><body>
<h1>ITDR Engine — Identity Threat Report</h1>
<div class="sub">Identity telemetry analysis &middot; MITRE ATT&amp;CK mapped &middot; {summary['total_events']} events ingested</div>
<div class="hero">
  <div><div class="big" style="color:{risk_color}">{risk_avg}</div><div class="bigl">Avg Risk Score</div></div>
  <div class="stats">
    <div class="s"><div class="n">{summary['total_events']}</div><div class="l">Events</div></div>
    <div class="s"><div class="n" style="color:#ff3b30">{summary['total_alerts']}</div><div class="l">Alerts</div></div>
    <div class="s"><div class="n" style="color:#ff9500">{summary['unique_users_flagged']}</div><div class="l">Users Flagged</div></div>
    <div class="s"><div class="n" style="color:#ff3b30">{summary['by_severity'].get('CRITICAL',0)}</div><div class="l">Critical</div></div>
    <div class="s"><div class="n" style="color:#ff9500">{summary['by_severity'].get('HIGH',0)}</div><div class="l">High</div></div>
  </div>
</div>
{''.join(rows)}
<div class="footer">ITDR Engine &middot; github.com/CyberEnthusiastic/itdr-engine</div>
<script>function toggle(i){{const b=document.getElementById('ab-'+i);b.classList.toggle('open');}}</script>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
