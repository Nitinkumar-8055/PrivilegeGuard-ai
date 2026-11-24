import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate
import html
import json
import logging
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from config import Config
from models import db, NotificationSetting, Incident, DetectionAlert

logger = logging.getLogger("privilegeguard.email")

def sanitize_header(val: str) -> str:
    """Strip CR and LF to prevent SMTP header injection."""
    if not val:
        return ""
    return re.sub(r"[\r\n]+", " ", str(val)).strip()

def is_valid_email(email_str: str) -> bool:
    """Validates standard email format."""
    if not email_str or not isinstance(email_str, str):
        return False
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, email_str.strip()))


class EmailService:
    """
    Production-grade, reusable email notification service using standard Python
    smtplib, ssl, and email.mime libraries configured for Gmail SMTP.
    """

    @classmethod
    def get_smtp_config(cls) -> Dict[str, Any]:
        """Resolves active SMTP configuration from database settings with environment fallback."""
        host = NotificationSetting.get("smtp_host") or os.environ.get("SMTP_HOST", "smtp.gmail.com")
        port = NotificationSetting.get("smtp_port") or int(os.environ.get("SMTP_PORT", 465))
        security = NotificationSetting.get("smtp_security") or os.environ.get("SMTP_SECURITY", "SSL")
        sender = NotificationSetting.get("smtp_sender") or os.environ.get("SMTP_EMAIL", "")
        # Password is NEVER stored in database; read strictly from environment
        password = os.environ.get("SMTP_PASSWORD", "")
        admin_email = NotificationSetting.get("admin_email") or os.environ.get("ADMIN_EMAIL", "nk8055444@gmail.com")
        email_enabled = NotificationSetting.get("email_enabled")
        if email_enabled is None:
            email_enabled = os.environ.get("EMAIL_NOTIFICATIONS_ENABLED", "true").lower() in ("true", "1", "yes")

        return {
            "host": host,
            "port": int(port),
            "security": str(security).upper(),
            "sender": sender or admin_email,
            "password": password,
            "admin_email": admin_email,
            "email_enabled": bool(email_enabled)
        }

    @classmethod
    def send_smtp_message(
        cls,
        recipient: str,
        subject: str,
        html_body: str,
        text_body: str,
        config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Transmits a multipart/alternative email message via configured Gmail SMTP.
        Handles timeouts, SSL/TLS negotiation, authentication, and connection failures.
        """
        cfg = config or cls.get_smtp_config()
        recipient = sanitize_header(recipient)
        subject = sanitize_header(subject)

        if not is_valid_email(recipient):
            err_msg = f"Invalid recipient email address format: '{recipient}'"
            logger.error(err_msg)
            return {"success": False, "error": err_msg}

        sender = cfg.get("sender") or cfg.get("admin_email")
        password = cfg.get("password")
        host = cfg.get("host", "smtp.gmail.com")
        port = cfg.get("port", 465)
        security = cfg.get("security", "SSL")

        if not password:
            err_msg = (
                "SMTP credentials unavailable: SMTP_PASSWORD is not set in environment or .env. "
                "Please configure your Gmail App Password to enable email transmissions."
            )
            logger.warning(err_msg)
            return {"success": False, "error": err_msg}

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = formataddr(("PrivilegeGuard AI Security Alert", sender))
        msg["To"] = recipient
        msg["Date"] = formatdate(localtime=True)
        msg["X-Priority"] = "1"  # Urgent
        msg["X-Mailer"] = "PrivilegeGuard AI Security Engine"

        # Plain text fallback
        part_text = MIMEText(text_body, "plain", "utf-8")
        msg.attach(part_text)

        # Rich HTML part
        part_html = MIMEText(html_body, "html", "utf-8")
        msg.attach(part_html)

        try:
            if security == "SSL" or port == 465:
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(host, port, context=context, timeout=15.0) as server:
                    server.login(sender, password)
                    server.send_message(msg)
            else:  # STARTTLS / port 587
                context = ssl.create_default_context()
                with smtplib.SMTP(host, port, timeout=15.0) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    server.login(sender, password)
                    server.send_message(msg)

            logger.info(f"Email successfully delivered to {recipient} via {host}:{port}")
            # Update success status in DB
            try:
                NotificationSetting.set("last_email_success", datetime.now(timezone.utc).isoformat())
                NotificationSetting.set("last_email_error", "")
                db.session.commit()
            except Exception:
                db.session.rollback()

            return {"success": True, "error": None}

        except smtplib.SMTPAuthenticationError as auth_err:
            err_str = (
                "Gmail SMTP Authentication Failed (535): Invalid username or Gmail App Password. "
                "Ensure 2-Step Verification is enabled and an active 16-character App Password is set in SMTP_PASSWORD."
            )
            logger.error(f"{err_str} Details: {auth_err}")
            cls._record_failure(err_str)
            return {"success": False, "error": err_str}

        except (smtplib.SMTPConnectError, ConnectionRefusedError, TimeoutError, OSError) as net_err:
            err_str = f"SMTP Connection Failed to {host}:{port} — {net_err}"
            logger.error(err_str)
            cls._record_failure(err_str)
            return {"success": False, "error": err_str}

        except Exception as exc:
            err_str = f"Unexpected SMTP dispatch error: {exc}"
            logger.error(err_str)
            cls._record_failure(err_str)
            return {"success": False, "error": err_str}

    @classmethod
    def _record_failure(cls, error_msg: str):
        """Persists failure timestamp and error diagnosis to settings."""
        try:
            NotificationSetting.set("last_email_failure", datetime.now(timezone.utc).isoformat())
            NotificationSetting.set("last_email_error", str(error_msg))
            db.session.commit()
        except Exception:
            db.session.rollback()

    @classmethod
    def send_test_email(cls, recipient: Optional[str] = None) -> Dict[str, Any]:
        """
        Sends an immediate verification test email to confirm Gmail SMTP credentials
        and TLS handshaking without generating an incident.
        """
        cfg = cls.get_smtp_config()
        target_email = recipient or cfg.get("admin_email")

        timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        subject = f"[PrivilegeGuard AI] Test Notification: Gmail SMTP Verification ({timestamp_str})"

        html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0a0e17; color: #f8fafc; margin: 0; padding: 24px; }}
  .container {{ max-width: 600px; margin: 0 auto; background-color: #0f1523; border: 1px solid #1e2c44; border-radius: 8px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
  .header {{ background: linear-gradient(135deg, #1e2c44 0%, #0f1523 100%); padding: 24px; border-bottom: 2px solid #38bdf8; display: flex; align-items: center; justify-content: space-between; }}
  .title {{ font-size: 20px; font-weight: 700; color: #38bdf8; margin: 0; }}
  .subtitle {{ font-size: 13px; color: #94a3b8; margin-top: 4px; }}
  .badge {{ background-color: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.4); padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; }}
  .content {{ padding: 24px; line-height: 1.6; color: #cbd5e1; font-size: 14px; }}
  .info-box {{ background-color: #131c2e; border: 1px solid #1e2c44; border-radius: 6px; padding: 16px; margin: 20px 0; }}
  .info-row {{ display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #1a253a; }}
  .info-row:last-child {{ border-bottom: none; }}
  .info-label {{ color: #94a3b8; font-size: 13px; }}
  .info-value {{ color: #f8fafc; font-weight: 600; font-family: monospace; font-size: 13px; }}
  .footer {{ background-color: #0a0e17; padding: 16px 24px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1e2c44; }}
</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h2 class="title">&#128737; PrivilegeGuard <span style="color:#ffffff;">AI</span></h2>
        <div class="subtitle">Intelligent Privilege Abuse Detection Platform</div>
      </div>
      <span class="badge">SMTP Verified</span>
    </div>
    <div class="content">
      <h3 style="color:#f8fafc; margin-top:0;">Gmail SMTP Diagnostic Verification</h3>
      <p>This is an automated test message sent by <strong>PrivilegeGuard AI</strong> to verify your Gmail SMTP outbound notification channel.</p>
      <div class="info-box">
        <div class="info-row"><span class="info-label">SMTP Host:</span><span class="info-value">{html.escape(cfg.get('host', ''))}</span></div>
        <div class="info-row"><span class="info-label">SMTP Port:</span><span class="info-value">{cfg.get('port')} ({html.escape(cfg.get('security', ''))})</span></div>
        <div class="info-row"><span class="info-label">Sender Account:</span><span class="info-value">{html.escape(cfg.get('sender', ''))}</span></div>
        <div class="info-row"><span class="info-label">Recipient Account:</span><span class="info-value">{html.escape(str(target_email))}</span></div>
        <div class="info-row"><span class="info-label">Timestamp:</span><span class="info-value">{timestamp_str}</span></div>
      </div>
      <p style="margin-bottom:0; color:#94a3b8; font-size:13px;">Security alerts matching your configured severity thresholds (CRITICAL and HIGH by default) will now be automatically dispatched to this inbox.</p>
    </div>
    <div class="footer">
      PrivilegeGuard AI Security Operations &bull; Automated Telemetry Dispatch &bull; Confidential
    </div>
  </div>
</body>
</html>"""

        text_body = f"""==================================================
PRIVILEGEGUARD AI — GMAIL SMTP TEST VERIFICATION
==================================================
This is an automated test message sent by PrivilegeGuard AI to verify your
Gmail SMTP notification channel.

SMTP Host:       {cfg.get('host')}
SMTP Port:       {cfg.get('port')} ({cfg.get('security')})
Sender Account:  {cfg.get('sender')}
Recipient:       {target_email}
Timestamp:       {timestamp_str}

Status:          VERIFIED & READY
Security alerts matching your configured severity thresholds will be
dispatched automatically to this inbox.
==================================================
"""
        res = cls.send_smtp_message(target_email, subject, html_body, text_body, cfg)
        return {
            "success": res.get("success", False),
            "recipient": target_email,
            "timestamp": timestamp_str,
            "error": res.get("error")
        }

    @classmethod
    def build_incident_email(
        cls,
        incident: Incident,
        is_escalation: bool = False,
        old_severity: Optional[str] = None,
        base_url: str = "http://127.0.0.1:5000"
    ) -> Dict[str, str]:
        """
        Builds a high-impact, cybersecurity-formatted HTML and plain-text email
        for a security incident or severity escalation.
        """
        sev = (incident.severity or "medium").upper()
        inc_id = incident.incident_id
        user = incident.affected_user or "Unknown Identity"
        title = incident.title
        risk_score = incident.risk_score

        # Distinct source IPs from supporting events
        source_ips: List[str] = []
        try:
            for ev in incident.events:
                if ev.source_ip and ev.source_ip not in source_ips:
                    source_ips.append(ev.source_ip)
        except Exception:
            pass
        source_ips_str = ", ".join(source_ips) if source_ips else "Internal / LocalHost"

        # Detection rules triggered
        alerts_data: List[Dict[str, str]] = []
        try:
            for alert in incident.alerts:
                alerts_data.append({
                    "id": alert.rule_id,
                    "name": alert.rule_name,
                    "reason": alert.reason
                })
        except Exception:
            pass

        # Timestamps
        first_obs = incident.first_observed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if incident.first_observed_at else "N/A"
        last_obs = incident.last_observed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if incident.last_observed_at else "N/A"
        created_ts = incident.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if incident.created_at else "N/A"

        # Severity colors
        color_map = {
            "CRITICAL": {"bg": "rgba(239, 68, 68, 0.2)", "border": "#ef4444", "text": "#ef4444"},
            "HIGH": {"bg": "rgba(249, 115, 22, 0.2)", "border": "#f97316", "text": "#f97316"},
            "MEDIUM": {"bg": "rgba(234, 179, 8, 0.2)", "border": "#eab308", "text": "#eab308"},
            "LOW": {"bg": "rgba(16, 185, 129, 0.2)", "border": "#10b981", "text": "#10b981"},
        }
        sev_color = color_map.get(sev, color_map["MEDIUM"])

        if is_escalation:
            subject = f"[PrivilegeGuard AI] [ESCALATION] Severity Raised to {sev}: {title} [{inc_id}]"
            banner_title = f"SECURITY INCIDENT SEVERITY ESCALATION &mdash; {sev}"
            banner_sub = f"Incident {inc_id} escalated from {(old_severity or 'previous').upper()} to {sev} (Risk Score: {risk_score}/100)"
        else:
            subject = f"[PrivilegeGuard AI] [{sev}] Security Incident: {title} [{inc_id}]"
            banner_title = f"QUALIFYING SECURITY INCIDENT CREATED &mdash; {sev}"
            banner_sub = f"Correlated attack pattern identified for user '{user}' (Risk Score: {risk_score}/100)"

        incident_url = f"{base_url.rstrip('/')}/incidents/{inc_id}"

        # Safe escaping
        safe_inc_id = html.escape(inc_id)
        safe_title = html.escape(title)
        safe_user = html.escape(user)
        safe_source_ips = html.escape(source_ips_str)
        safe_summary = html.escape(incident.summary or "Automated correlation detected multi-signal privilege anomalies.")

        # Build rules HTML list
        rules_html = ""
        for a in alerts_data:
            rules_html += f"""<div style="background:#131c2e; border-left:3px solid {sev_color['border']}; padding:10px 14px; margin-bottom:8px; border-radius:4px;">
              <div style="font-weight:700; color:#f8fafc; font-size:13px;">{html.escape(a['id'])} &mdash; {html.escape(a['name'])}</div>
              <div style="color:#94a3b8; font-size:12px; margin-top:3px;">{html.escape(a['reason'])}</div>
            </div>"""

        if not rules_html:
            rules_html = "<div style='color:#94a3b8; font-style:italic;'>Rule signature correlation in progress.</div>"

        # Playbook actions
        actions_list: List[str] = []
        try:
            if incident.recommended_actions:
                actions_list = json.loads(incident.recommended_actions)
        except Exception:
            actions_list = []
        if not actions_list:
            actions_list = [
                "Review user authentication history and active sessions",
                "Validate role modification authorizations with directory owners",
                "Initiate immediate account containment if unauthorized"
            ]

        playbook_html = "".join([f"<li style='margin-bottom:6px; color:#cbd5e1;'>{html.escape(act)}</li>" for act in actions_list])

        html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0a0e17; color: #f8fafc; margin: 0; padding: 24px; }}
  .container {{ max-width: 660px; margin: 0 auto; background-color: #0f1523; border: 1px solid #1e2c44; border-radius: 8px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.6); }}
  .header {{ background: #0b111e; padding: 20px 24px; border-bottom: 2px solid {sev_color['border']}; display: flex; align-items: center; justify-content: space-between; }}
  .title {{ font-size: 19px; font-weight: 700; color: #38bdf8; margin: 0; }}
  .badge {{ background-color: {sev_color['bg']}; color: {sev_color['text']}; border: 1px solid {sev_color['border']}; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 700; letter-spacing: 0.5px; }}
  .banner {{ background-color: #131c2e; padding: 16px 24px; border-bottom: 1px solid #1e2c44; }}
  .content {{ padding: 24px; font-size: 14px; line-height: 1.6; color: #cbd5e1; }}
  .grid {{ display: table; width: 100%; margin: 16px 0; border: 1px solid #1e2c44; border-radius: 6px; overflow: hidden; }}
  .row {{ display: table-row; background: #131c2e; }}
  .row:nth-child(even) {{ background: #0f1523; }}
  .cell-lbl {{ display: table-cell; padding: 10px 14px; color: #94a3b8; font-size: 13px; width: 35%; border-bottom: 1px solid #1a253a; }}
  .cell-val {{ display: table-cell; padding: 10px 14px; color: #f8fafc; font-weight: 600; font-size: 13px; border-bottom: 1px solid #1a253a; }}
  .btn {{ display: inline-block; background: linear-gradient(135deg, #2563eb 0%, #7c3aed 100%); color: #ffffff !important; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: 600; font-size: 14px; margin-top: 16px; text-align: center; }}
  .footer {{ background-color: #0a0e17; padding: 16px 24px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1e2c44; }}
</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h2 class="title">&#128737; PrivilegeGuard <span style="color:#ffffff;">AI</span></h2>
        <div style="font-size:12px; color:#94a3b8; margin-top:2px;">Privilege Escalation & Abuse Detection</div>
      </div>
      <span class="badge">{sev} ALERT</span>
    </div>
    <div class="banner">
      <div style="font-weight:700; color:{sev_color['text']}; font-size:15px;">{banner_title}</div>
      <div style="font-size:13px; color:#94a3b8; margin-top:4px;">{banner_sub}</div>
    </div>
    <div class="content">
      <h3 style="color:#f8fafc; margin-top:0; font-size:16px;">{safe_title}</h3>
      <div class="grid">
        <div class="row"><div class="cell-lbl">Incident ID</div><div class="cell-val" style="font-family:monospace; color:#38bdf8;">{safe_inc_id}</div></div>
        <div class="row"><div class="cell-lbl">Severity & Risk Score</div><div class="cell-val" style="color:{sev_color['text']};">{sev} &mdash; Risk Score {risk_score}/100</div></div>
        <div class="row"><div class="cell-lbl">Affected Identity</div><div class="cell-val" style="color:#f8fafc;">{safe_user}</div></div>
        <div class="row"><div class="cell-lbl">Source IP Address(es)</div><div class="cell-val" style="font-family:monospace;">{safe_source_ips}</div></div>
        <div class="row"><div class="cell-lbl">Investigation Status</div><div class="cell-val">{html.escape(incident.status)}</div></div>
        <div class="row"><div class="cell-lbl">Observation Window</div><div class="cell-val" style="font-size:12px;">{first_obs} &rarr; {last_obs}</div></div>
        <div class="row"><div class="cell-lbl">Dispatched At</div><div class="cell-val" style="font-size:12px;">{created_ts}</div></div>
      </div>

      <div style="margin:20px 0;">
        <h4 style="color:#f8fafc; margin-bottom:8px; font-size:14px;">Incident Threat Summary</h4>
        <div style="background:#131c2e; padding:12px 16px; border-radius:6px; border:1px solid #1e2c44; color:#cbd5e1; font-size:13px;">
          {safe_summary}
        </div>
      </div>

      <div style="margin:20px 0;">
        <h4 style="color:#f8fafc; margin-bottom:8px; font-size:14px;">Triggered Detection Rules ({len(alerts_data)})</h4>
        {rules_html}
      </div>

      <div style="margin:20px 0;">
        <h4 style="color:#f8fafc; margin-bottom:8px; font-size:14px;">Recommended Analyst Actions</h4>
        <ul style="padding-left:20px; margin:0;">
          {playbook_html}
        </ul>
      </div>

      <div style="text-align:center; padding:16px 0;">
        <a href="{incident_url}" class="btn">Open Incident Investigation Dashboard &rarr;</a>
        <div style="font-size:11px; color:#64748b; margin-top:8px;">Direct reference: {safe_inc_id}</div>
      </div>
    </div>
    <div class="footer">
      PrivilegeGuard AI Cybersecurity Telemetry &bull; Automated Security Dispatch &bull; Recipient: nk8055444@gmail.com
    </div>
  </div>
</body>
</html>"""

        # Plain-text ASCII version
        rules_text = "\n".join([f"  * [{a['id']}] {a['name']}: {a['reason']}" for a in alerts_data]) or "  * (No specific rules cataloged)"
        playbook_text = "\n".join([f"  * {act}" for act in actions_list])

        text_body = f"""======================================================================
PRIVILEGEGUARD AI — SECURITY INCIDENT NOTIFICATION [{sev}]
======================================================================
Incident ID:          {inc_id}
Title:                {title}
Severity:             {sev}
Risk Score:           {risk_score}/100
Affected Identity:    {user}
Source IP(s):         {source_ips_str}
Investigation Status: {incident.status}
Observation Window:   {first_obs} -> {last_obs}
Incident Created At:  {created_ts}

----------------------------------------------------------------------
THREAT SUMMARY:
----------------------------------------------------------------------
{incident.summary or 'Automated correlation detected multi-signal privilege anomalies.'}

----------------------------------------------------------------------
TRIGGERED DETECTION RULES:
----------------------------------------------------------------------
{rules_text}

----------------------------------------------------------------------
RECOMMENDED ANALYST ACTIONS:
----------------------------------------------------------------------
{playbook_text}

----------------------------------------------------------------------
DASHBOARD LINK:
----------------------------------------------------------------------
{incident_url}

PrivilegeGuard AI — Intelligent Privilege Abuse Detection Platform
Confidential Security Notice.
======================================================================
"""
        return {
            "subject": subject,
            "html_body": html_body,
            "text_body": text_body
        }
