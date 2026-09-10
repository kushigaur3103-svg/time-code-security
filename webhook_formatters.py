"""
TimeCodeSecurity (TCS) Webhook Payload Formatters & Sanitization.

Defines:
- MAX_WEBHOOK_PAYLOAD_BYTES = 65536 (Universal 64 KB ceiling).
- GenericWebhookFormatter: Standard JSON schema with schema_version: 1.
- SlackWebhookFormatter: Block Kit format with XML entity escaping and mention neutralization.
- DiscordWebhookFormatter: Embed format with markdown sanitization and mention neutralization.
- PayloadTooLargeError: Raised before network transmission if bytes > 65536.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from notification_policy import NotificationIntent, SafeFindingSummary

MAX_WEBHOOK_PAYLOAD_BYTES = 65536  # 64 KB exact ceiling


class PayloadTooLargeError(Exception):
    """Raised when serialized webhook payload exceeds MAX_WEBHOOK_PAYLOAD_BYTES before network transmission."""
    pass


def escape_slack_text(text: str) -> str:
    """
    Escapes Slack mrkdwn control characters in untrusted strings:
    - & -> &amp;
    - < -> &lt;
    - > -> &gt;
    This neutralizes mention injections (<@U123>, <!everyone>, <!here>).
    """
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def escape_discord_text(text: str) -> str:
    """
    Sanitizes untrusted text for Discord embeds:
    - Injects zero-width space into @everyone and @here
    - Injects zero-width space into raw mention syntax (<@, <@&)
    """
    if not text:
        return ""
    sanitized = text.replace("@everyone", "@\u200beveryone").replace("@here", "@\u200bhere")
    sanitized = sanitized.replace("<@", "<\u200b@").replace("<@&", "<\u200b@&")
    return sanitized


class GenericWebhookFormatter:
    """
    Default JSON payload formatter.
    Enforces schema_version: 1 and strict 64 KB ceiling.
    """

    @staticmethod
    def format(intent: NotificationIntent) -> bytes:
        findings_payload: List[Dict[str, Any]] = [
            {
                "rule_id": f.rule_id,
                "cwe": f.cwe,
                "severity": f.severity,
                "file_path": f.file_path,
                "line": f.line,
                "message": f.message,
            }
            for f in intent.safe_findings
        ]

        payload_obj = {
            "schema_version": 1,
            "event_id": intent.event_id,
            "scan_id": intent.scan_id,
            "organization_id": intent.organization_id,
            "notification_type": intent.notification_type,
            "severity": intent.severity,
            "title": intent.title,
            "message": intent.message,
            "link": intent.link,
            "created_at": intent.created_at,
            "findings_truncated": intent.findings_truncated,
            "total_findings": intent.total_findings,
            "findings": findings_payload,
        }

        payload_bytes = json.dumps(payload_obj, ensure_ascii=False, indent=None).encode("utf-8")
        if len(payload_bytes) > MAX_WEBHOOK_PAYLOAD_BYTES:
            raise PayloadTooLargeError(
                f"Generic webhook payload exceeds {MAX_WEBHOOK_PAYLOAD_BYTES} bytes ({len(payload_bytes)} bytes)."
            )
        return payload_bytes


class SlackWebhookFormatter:
    """
    Formats NotificationIntent into Slack Block Kit payload.
    Escapes all dynamic text and enforces section/block limits.
    """

    @staticmethod
    def format(intent: NotificationIntent) -> bytes:
        safe_title = escape_slack_text(intent.title)[:2000]
        safe_msg = escape_slack_text(intent.message)[:2000]
        safe_sev = escape_slack_text(intent.severity)

        blocks: List[Dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": safe_title[:150],
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Severity:* `{safe_sev}`\n{safe_msg}",
                },
            },
        ]

        # Add findings summary blocks (up to 10 findings, max 15 total blocks)
        for idx, finding in enumerate(intent.safe_findings[:10]):
            f_rule = escape_slack_text(finding.rule_id)
            f_cwe = escape_slack_text(finding.cwe)
            f_path = escape_slack_text(finding.file_path)
            f_line = f":{finding.line}" if finding.line else ""
            f_msg = escape_slack_text(finding.message)

            block_text = f"• *{f_rule}* ({f_cwe}) [{finding.severity}]\n  `{f_path}{f_line}` — {f_msg}"
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": block_text[:2000],
                },
            })
            if len(blocks) >= 14:
                break

        if intent.findings_truncated or intent.total_findings > len(intent.safe_findings):
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Showing {len(intent.safe_findings)} of {intent.total_findings} findings. View full scan in dashboard.",
                    }
                ],
            })

        payload_obj = {
            "text": safe_title[:2000],
            "blocks": blocks[:15],
        }

        payload_bytes = json.dumps(payload_obj, ensure_ascii=False).encode("utf-8")
        if len(payload_bytes) > MAX_WEBHOOK_PAYLOAD_BYTES:
            raise PayloadTooLargeError(
                f"Slack webhook payload exceeds {MAX_WEBHOOK_PAYLOAD_BYTES} bytes ({len(payload_bytes)} bytes)."
            )
        return payload_bytes


class DiscordWebhookFormatter:
    """
    Formats NotificationIntent into Discord Embed payload.
    Sanitizes markdown and neutralizes mass mentions (@everyone, @here).
    """

    @staticmethod
    def format(intent: NotificationIntent) -> bytes:
        safe_title = escape_discord_text(intent.title)[:250]
        safe_desc = escape_discord_text(intent.message)[:2000]

        # Severity color mapping
        colors = {
            "CRITICAL": 0xFF0000,  # Red
            "HIGH": 0xFF5500,      # Orange
            "MEDIUM": 0xFFAA00,    # Amber
            "LOW": 0x00AAFF,       # Light Blue
            "INFO": 0x888888,      # Grey
        }
        color = colors.get(intent.severity.upper(), 0x888888)

        fields: List[Dict[str, Any]] = [
            {"name": "Severity", "value": f"`{intent.severity}`", "inline": True},
            {"name": "Total Findings", "value": str(intent.total_findings), "inline": True},
        ]

        for finding in intent.safe_findings[:5]:
            f_rule = escape_discord_text(finding.rule_id)[:64]
            f_path = escape_discord_text(finding.file_path)[:128]
            f_line = f":{finding.line}" if finding.line else ""
            f_msg = escape_discord_text(finding.message)[:255]
            fields.append({
                "name": f"{f_rule} [{finding.severity}]",
                "value": f"`{f_path}{f_line}`\n{f_msg}",
                "inline": False,
            })

        embed = {
            "title": safe_title,
            "description": safe_desc,
            "color": color,
            "fields": fields,
        }
        if intent.link:
            embed["url"] = intent.link

        payload_obj = {
            "embeds": [embed]
        }

        payload_bytes = json.dumps(payload_obj, ensure_ascii=False).encode("utf-8")
        if len(payload_bytes) > MAX_WEBHOOK_PAYLOAD_BYTES:
            raise PayloadTooLargeError(
                f"Discord webhook payload exceeds {MAX_WEBHOOK_PAYLOAD_BYTES} bytes ({len(payload_bytes)} bytes)."
            )
        return payload_bytes


def format_webhook_payload(intent: NotificationIntent, format_type: str = "GENERIC") -> bytes:
    """
    Factory function formatting a NotificationIntent into wire bytes
    using the specified format ("GENERIC", "SLACK", or "DISCORD").
    """
    fmt = format_type.upper().strip()
    if fmt == "SLACK":
        return SlackWebhookFormatter.format(intent)
    elif fmt == "DISCORD":
        return DiscordWebhookFormatter.format(intent)
    else:
        return GenericWebhookFormatter.format(intent)
