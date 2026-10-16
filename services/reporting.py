import json
from datetime import datetime, timezone
from typing import Dict, Any, List
from models import Incident, SecurityEvent

class ReportingService:
    """Generates structured JSON and styled, printable HTML security incident reports."""

    @classmethod
    def generate_incident_json(cls, incident: Incident) -> Dict[str, Any]:
        """Generate structured JSON report for a specific incident."""
        report = {
            "report_metadata": {
                "platform": "PrivilegeGuard AI",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "report_type": "Security Incident Forensic Report",
                "version": "1.0.0"
            },
            "incident_details": incident.to_dict(include_events=True),
            "executive_summary": incident.summary,
            "soc_recommendations": json.loads(incident.recommended_actions) if incident.recommended_actions else []
        }
        return report

    @classmethod
    def generate_incident_html(cls, incident: Incident) -> str:
        """Generate a complete standalone, beautifully styled HTML incident report."""
        inc_data = incident.to_dict(include_events=True)
        factors = inc_data.get("risk_factors", [])
        events = inc_data.get("events", [])
        alerts = inc_data.get("alerts", [])
        actions = inc_data.get("recommended_actions", [])
        ai_exp = inc_data.get("ai_explanation", {})

        # Color based on severity
        sev = inc_data.get("severity", "medium").lower()
        sev_color = "#f43f5e" if sev == "critical" else "#f97316" if sev == "high" else "#eab308" if sev == "medium" else "#10b981"

        events_rows = ""
        for ev in events:
            events_rows += f"""
            <tr>
                <td style="padding: 10px; border-bottom: 1px solid #2d3748; font-family: monospace;">{ev.get('timestamp', '')}</td>
                <td style="padding: 10px; border-bottom: 1px solid #2d3748;"><span style="background: #1e293b; padding: 3px 8px; border-radius: 4px; font-family: monospace; font-size: 12px;">{ev.get('event_type')}</span></td>
                <td style="padding: 10px; border-bottom: 1px solid #2d3748;">{ev.get('actor') or 'N/A'}</td>
                <td style="padding: 10px; border-bottom: 1px solid #2d3748;">{ev.get('old_role') or '-'} &rarr; {ev.get('new_role') or '-'}</td>
                <td style="padding: 10px; border-bottom: 1px solid #2d3748;">{ev.get('resource') or 'N/A'}</td>
                <td style="padding: 10px; border-bottom: 1px solid #2d3748;">{ev.get('outcome')}</td>
                <td style="padding: 10px; border-bottom: 1px solid #2d3748; font-family: monospace;">{ev.get('source_ip') or 'N/A'}</td>
            </tr>
            """

        factors_html = ""
        for f in factors:
            factors_html += f"""
            <div style="background: #1e293b; padding: 12px; border-radius: 6px; margin-bottom: 8px; border-left: 4px solid #38bdf8;">
                <div style="display: flex; justify-content: space-between; font-weight: 600;">
                    <span>{f.get('factor')}</span>
                    <span style="color: #38bdf8;">+{f.get('points')} pts</span>
                </div>
                <div style="font-size: 13px; color: #94a3b8; margin-top: 4px;">{f.get('description')}</div>
            </div>
            """

        alerts_html = ""
        for a in alerts:
            alerts_html += f"""
            <div style="background: #1e293b; padding: 14px; border-radius: 6px; margin-bottom: 12px; border: 1px solid #334155;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 700; color: #e2e8f0;">[{a.get('rule_id')}] {a.get('rule_name')}</span>
                    <span style="background: {sev_color}22; color: {sev_color}; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; text-transform: uppercase;">{a.get('severity')}</span>
                </div>
                <div style="margin-top: 8px; font-size: 14px; color: #cbd5e1;">{a.get('reason')}</div>
            </div>
            """

        actions_html = ""
        for act in actions:
            actions_html += f"<li style='margin-bottom: 6px; color: #cbd5e1;'>{act}</li>"

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PrivilegeGuard AI - Incident Report {inc_data.get('incident_id')}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #0f172a;
            color: #f8fafc;
            margin: 0;
            padding: 40px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
        }}
        .header {{
            border-bottom: 2px solid #1f2937;
            padding-bottom: 20px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .badge {{
            padding: 6px 14px;
            border-radius: 9999px;
            font-weight: bold;
            font-size: 14px;
            text-transform: uppercase;
        }}
        h1, h2, h3 {{ color: #f8fafc; margin-top: 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; text-align: left; }}
        th {{ background: #1f2937; padding: 10px; color: #94a3b8; font-weight: 600; }}
        .score-box {{
            background: #0b0f19;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .container {{ border: none; box-shadow: none; padding: 20px; background: #fff; color: #000; }}
            th {{ background: #eee; color: #000; }}
            td {{ border-bottom: 1px solid #ccc !important; }}
            .score-box {{ background: #f8f9fa; border: 1px solid #ddd; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div style="font-size: 12px; text-transform: uppercase; letter-spacing: 0.1em; color: #38bdf8; font-weight: bold;">PrivilegeGuard AI Security Intelligence</div>
                <h1 style="margin: 8px 0 4px 0; font-size: 26px;">Forensic Incident Report: {inc_data.get('incident_id')}</h1>
                <div style="color: #94a3b8; font-size: 14px;">Title: {inc_data.get('title')}</div>
            </div>
            <div style="text-align: right;">
                <span class="badge" style="background: {sev_color}22; color: {sev_color}; border: 1px solid {sev_color};">{sev.upper()} SEVERITY</span>
                <div style="font-size: 12px; color: #94a3b8; margin-top: 8px;">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>
            </div>
        </div>

        <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-bottom: 30px;">
            <div style="background: #1e293b; padding: 20px; border-radius: 8px;">
                <h3 style="margin-bottom: 10px; color: #38bdf8;">Executive Incident Summary</h3>
                <p style="color: #cbd5e1; font-size: 14px; margin: 0;">{inc_data.get('summary') or 'No summary recorded.'}</p>
                <div style="margin-top: 15px; font-size: 13px; color: #94a3b8;">
                    <strong>Affected Identity:</strong> <code style="color: #38bdf8;">{inc_data.get('affected_user')}</code> |
                    <strong>Status:</strong> {inc_data.get('status')} |
                    <strong>First Seen:</strong> {inc_data.get('first_observed_at')}
                </div>
            </div>
            <div class="score-box">
                <div style="font-size: 13px; text-transform: uppercase; color: #94a3b8; font-weight: bold;">Calculated Risk Score</div>
                <div style="font-size: 48px; font-weight: 800; color: {sev_color}; margin: 8px 0;">{inc_data.get('risk_score')}<span style="font-size: 20px; color: #64748b;">/100</span></div>
                <div style="font-size: 12px; color: #94a3b8;">Normalized Risk Level: <strong>{sev.upper()}</strong></div>
            </div>
        </div>

        <div style="margin-bottom: 30px;">
            <h3>Security Detection Rules Triggered</h3>
            {alerts_html}
        </div>

        <div style="margin-bottom: 30px;">
            <h3>Explainable Risk Factors</h3>
            {factors_html}
        </div>

        <div style="margin-bottom: 30px; background: #1e293b; padding: 20px; border-radius: 8px;">
            <h3 style="color: #38bdf8;">Analytical Reasoning & Benign Interpretations</h3>
            <div style="font-size: 14px; margin-bottom: 12px;">
                <strong style="color: #f1f5f9;">Why Flagged:</strong>
                <p style="color: #cbd5e1; margin-top: 4px;">{ai_exp.get('why_flagged', 'N/A')}</p>
            </div>
            <div style="font-size: 14px; margin-bottom: 12px;">
                <strong style="color: #f1f5f9;">Potential Benign Interpretation:</strong>
                <p style="color: #94a3b8; margin-top: 4px;">{ai_exp.get('benign_explanation', 'N/A')}</p>
            </div>
            <div style="font-size: 14px;">
                <strong style="color: #f1f5f9;">Analytical Uncertainties:</strong>
                <p style="color: #94a3b8; margin-top: 4px;">{ai_exp.get('uncertainties', 'N/A')}</p>
            </div>
        </div>

        <div style="margin-bottom: 30px;">
            <h3>Recommended SOC Response Playbook</h3>
            <ul style="background: #1e293b; padding: 20px 30px; border-radius: 8px; font-size: 14px;">
                {actions_html}
            </ul>
        </div>

        <div>
            <h3>Correlated Event Timeline & Supporting Forensic Evidence</h3>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Event Type</th>
                        <th>Actor</th>
                        <th>Role Transition</th>
                        <th>Target Resource</th>
                        <th>Outcome</th>
                        <th>Source IP</th>
                    </tr>
                </thead>
                <tbody>
                    {events_rows}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
        return html_doc
