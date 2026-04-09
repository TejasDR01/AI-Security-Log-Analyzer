"""
Log Parser – Normalizes multiple log formats into structured JSON events.
Supports: SSH auth logs, Web server logs, Firewall logs, Application logs.
"""

import re
import json
from datetime import datetime
from typing import Optional

# ─── Regex Patterns ───────────────────────────────────────────────────────────

# Timestamps
TS_SYSLOG     = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'           # Jan  5 12:34:56
TS_ISO        = r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
TS_COMBINED   = r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})' # Apache combined
TS_EPOCH      = r'(\d{10,13})'

# IP Address
IP_PATTERN    = r'(\d{1,3}(?:\.\d{1,3}){3})'

# SSH Patterns
SSH_FAILED    = re.compile(
    rf'{TS_SYSLOG}\s+\S+\s+sshd\[(\d+)\]:\s+Failed (\w+) for (?:invalid user )?(\S+) from {IP_PATTERN} port (\d+)',
    re.IGNORECASE
)
SSH_ACCEPTED  = re.compile(
    rf'{TS_SYSLOG}\s+\S+\s+sshd\[(\d+)\]:\s+Accepted (\w+) for (\S+) from {IP_PATTERN} port (\d+)',
    re.IGNORECASE
)
SSH_INVALID   = re.compile(
    rf'{TS_SYSLOG}\s+\S+\s+sshd\[(\d+)\]:\s+Invalid user (\S+) from {IP_PATTERN}',
    re.IGNORECASE
)
SSH_DISCONNECT = re.compile(
    rf'{TS_SYSLOG}\s+\S+\s+sshd\[(\d+)\]:\s+(?:Disconnected|Connection closed) (?:from|by).*?{IP_PATTERN}',
    re.IGNORECASE
)

# Auth/sudo Patterns
SUDO_PATTERN  = re.compile(
    rf'{TS_SYSLOG}\s+\S+\s+sudo.*?:\s+(\S+)\s+:.*?COMMAND=(.*)',
    re.IGNORECASE
)
AUTH_FAIL     = re.compile(
    rf'{TS_SYSLOG}\s+\S+\s+\S+\[(\d+)\]:\s+authentication failure.*?user=(\S+)',
    re.IGNORECASE
)

# Web Server Patterns (Combined Log Format)
APACHE_NGINX  = re.compile(
    rf'{IP_PATTERN}\s+-\s+(\S+)\s+\[{TS_COMBINED}\]\s+"(\w+)\s+(\S+)\s+\S+"\s+(\d{{3}})\s+(\d+|-)',
    re.IGNORECASE
)
APACHE_SIMPLE = re.compile(
    rf'{IP_PATTERN}.*?"(\w+)\s+(\S+)\s+HTTP/[\d.]+"\s+(\d{{3}})\s+(\d+|-)',
    re.IGNORECASE
)

# Firewall Patterns
UFW_PATTERN   = re.compile(
    rf'{TS_SYSLOG}\s+\S+\s+kernel.*?UFW\s+(\w+).*?SRC={IP_PATTERN}.*?DST={IP_PATTERN}.*?PROTO=(\w+).*?DPT=(\d+)',
    re.IGNORECASE
)
IPTABLES_PATTERN = re.compile(
    rf'{TS_SYSLOG}\s+\S+\s+kernel.*?IN=(\S*)\s+OUT=(\S*)\s+.*?SRC={IP_PATTERN}\s+DST={IP_PATTERN}.*?PROTO=(\w+)',
    re.IGNORECASE
)

# Generic fallback
GENERIC_TS_IP = re.compile(
    rf'(?:{TS_ISO}|{TS_SYSLOG}).*?{IP_PATTERN}',
    re.IGNORECASE
)
GENERIC_USER  = re.compile(r'user[=:\s]+([a-zA-Z0-9_\-\.]+)', re.IGNORECASE)
GENERIC_STATUS= re.compile(r'\b([2345]\d{2})\b')


# ─── Parser Class ─────────────────────────────────────────────────────────────

class LogParser:
    def parse(self, raw_text: str, log_type: str = "auto") -> dict:
        lines = [l for l in raw_text.splitlines() if l.strip()]
        detected_type = log_type if log_type != "auto" else self._detect_type(lines)

        parsers = {
            "ssh":         self._parse_ssh_line,
            "auth":        self._parse_auth_line,
            "web":         self._parse_web_line,
            "firewall":    self._parse_firewall_line,
            "application": self._parse_application_line,
            "json":        self._parse_json_line,
        }

        parser_fn = parsers.get(detected_type, self._parse_generic_line)
        events = []
        for i, line in enumerate(lines):
            event = parser_fn(line, line_num=i + 1)
            if event:
                events.append(event)

        return {
            "total_lines": len(lines),
            "events": events,
            "detected_type": detected_type,
            "unique_ips": list({e["source_ip"] for e in events if e.get("source_ip")}),
            "unique_users": list({e["username"] for e in events if e.get("username")}),
        }

    # ── Type Detection ─────────────────────────────────────────────────────────

    def _detect_type(self, lines: list) -> str:
        sample = "\n".join(lines[:30]).lower()
        if "sshd" in sample or "ssh" in sample:
            return "ssh"
        if "ufw" in sample or "iptables" in sample or "firewall" in sample:
            return "firewall"
        if re.search(r'"(get|post|put|delete|head)\s+/', sample):
            return "web"
        if "authentication failure" in sample or "sudo" in sample or "pam" in sample:
            return "auth"
        try:
            json.loads(lines[0])
            return "json"
        except Exception:
            pass
        return "application"

    # ── SSH Parser ─────────────────────────────────────────────────────────────

    def _parse_ssh_line(self, line: str, line_num: int = 0) -> Optional[dict]:
        m = SSH_FAILED.search(line)
        if m:
            return self._event(line_num, m.group(1), "ssh_failed_login",
                               source_ip=m.group(5), username=m.group(4),
                               port=int(m.group(6)), auth_method=m.group(3),
                               severity="medium")

        m = SSH_ACCEPTED.search(line)
        if m:
            return self._event(line_num, m.group(1), "ssh_successful_login",
                               source_ip=m.group(5), username=m.group(4),
                               port=int(m.group(6)), auth_method=m.group(3),
                               severity="info")

        m = SSH_INVALID.search(line)
        if m:
            return self._event(line_num, m.group(1), "ssh_invalid_user",
                               source_ip=m.group(3), username=m.group(2),
                               severity="medium")

        m = SSH_DISCONNECT.search(line)
        if m:
            return self._event(line_num, m.group(1), "ssh_disconnect",
                               source_ip=m.group(3), severity="info")

        return self._parse_generic_line(line, line_num)

    # ── Auth Parser ────────────────────────────────────────────────────────────

    def _parse_auth_line(self, line: str, line_num: int = 0) -> Optional[dict]:
        if "sshd" in line.lower():
            return self._parse_ssh_line(line, line_num)

        m = SUDO_PATTERN.search(line)
        if m:
            return self._event(line_num, m.group(1), "sudo_command",
                               username=m.group(2), details=m.group(3).strip(),
                               severity="low")

        m = AUTH_FAIL.search(line)
        if m:
            return self._event(line_num, m.group(1), "auth_failure",
                               username=m.group(4), severity="medium")

        return self._parse_generic_line(line, line_num)

    # ── Web Parser ─────────────────────────────────────────────────────────────

    def _parse_web_line(self, line: str, line_num: int = 0) -> Optional[dict]:
        m = APACHE_NGINX.search(line)
        if m:
            status = int(m.group(6))                        
            sev = "high" if status >= 500 else ("medium" if status in (401, 403, 404) else "info")
            return self._event(line_num, None, "http_request",
                       source_ip=m.group(1), username=m.group(2),
                       http_method=m.group(4),      
                       url=m.group(5),              
                       status_code=status, severity=sev)

        m = APACHE_SIMPLE.search(line)
        if m:
            status = int(m.group(4))
            sev = "high" if status >= 500 else ("medium" if status in (401, 403, 404) else "info")
            return self._event(line_num, None, "http_request",
                               source_ip=m.group(1), http_method=m.group(2),
                               url=m.group(3), status_code=status, severity=sev)

        return self._parse_generic_line(line, line_num)

    # ── Firewall Parser ────────────────────────────────────────────────────────

    def _parse_firewall_line(self, line: str, line_num: int = 0) -> Optional[dict]:
        m = UFW_PATTERN.search(line)
        if m:
            action = m.group(2).lower()
            sev = "high" if action == "block" else "info"
            return self._event(line_num, m.group(1), f"firewall_{action}",
                               source_ip=m.group(3), dest_ip=m.group(4),
                               protocol=m.group(5), dest_port=int(m.group(6)),
                               severity=sev)

        m = IPTABLES_PATTERN.search(line)
        if m:
            return self._event(line_num, m.group(1), "firewall_packet",
                               source_ip=m.group(4), dest_ip=m.group(5),
                               protocol=m.group(6), severity="medium")

        return self._parse_generic_line(line, line_num)

    # ── Application Parser ────────────────────────────────────────────────────

    def _parse_application_line(self, line: str, line_num: int = 0) -> Optional[dict]:
        # Try ISO timestamp
        m = re.search(TS_ISO, line)
        ts_str = m.group(1) if m else None
        ip_m = re.search(IP_PATTERN, line)
        user_m = GENERIC_USER.search(line)
        status_m = GENERIC_STATUS.search(line)

        level = "info"
        line_lower = line.lower()
        if any(w in line_lower for w in ("error", "critical", "fatal", "exception")):
            level = "high"
        elif any(w in line_lower for w in ("warn", "warning", "denied", "forbidden")):
            level = "medium"

        event_type = "app_error" if level == "high" else "app_event"

        return self._event(line_num, ts_str, event_type,
                           source_ip=ip_m.group(1) if ip_m else None,
                           username=user_m.group(1) if user_m else None,
                           status_code=int(status_m.group(1)) if status_m else None,
                           details=line[:200],
                           severity=level)

    # ── JSON Parser ───────────────────────────────────────────────────────────

    def _parse_json_line(self, line: str, line_num: int = 0) -> Optional[dict]:
        try:
            obj = json.loads(line)
        except Exception:
            return self._parse_generic_line(line, line_num)

        ts = obj.get("timestamp") or obj.get("time") or obj.get("@timestamp")
        ip = obj.get("src_ip") or obj.get("source_ip") or obj.get("remote_addr") or obj.get("ip")
        user = obj.get("user") or obj.get("username") or obj.get("user_name")
        etype = obj.get("event") or obj.get("event_type") or obj.get("type") or "json_event"
        status = obj.get("status") or obj.get("status_code") or obj.get("http_status")
        sev_raw = obj.get("severity") or obj.get("level") or "info"

        sev_map = {"critical": "high", "error": "high", "warning": "medium",
                   "warn": "medium", "info": "info", "debug": "info"}
        severity = sev_map.get(str(sev_raw).lower(), "info")

        return self._event(line_num, ts, etype,
                           source_ip=ip, username=user, status_code=status,
                           details=str(obj)[:200], severity=severity)

    # ── Generic Fallback ──────────────────────────────────────────────────────

    def _parse_generic_line(self, line: str, line_num: int = 0) -> Optional[dict]:
        ip_m = re.search(IP_PATTERN, line)
        ts_m = re.search(TS_ISO, line) or re.search(TS_SYSLOG, line)
        user_m = GENERIC_USER.search(line)
        status_m = GENERIC_STATUS.search(line)

        sev = "info"
        ll = line.lower()
        if any(w in ll for w in ("fail", "error", "denied", "invalid", "attack", "blocked")):
            sev = "medium"
        if any(w in ll for w in ("critical", "alert", "exploit", "malware", "intrusion")):
            sev = "high"

        return self._event(line_num,
                           ts_m.group(1) if ts_m else None,
                           "log_event",
                           source_ip=ip_m.group(1) if ip_m else None,
                           username=user_m.group(1) if user_m else None,
                           status_code=int(status_m.group(1)) if status_m else None,
                           details=line[:200],
                           severity=sev)

    # ── Event Builder ─────────────────────────────────────────────────────────

    def _event(self, line_num: int, timestamp_raw: Optional[str],
               event_type: str, **kwargs) -> dict:
        ts_parsed = self._parse_timestamp(timestamp_raw)
        return {
            "line_num":     line_num,
            "timestamp":    ts_parsed,
            "timestamp_raw": timestamp_raw,
            "event_type":  event_type,
            "source_ip":   kwargs.get("source_ip"),
            "dest_ip":     kwargs.get("dest_ip"),
            "username":    kwargs.get("username"),
            "port":        kwargs.get("port"),
            "dest_port":   kwargs.get("dest_port"),
            "protocol":    kwargs.get("protocol"),
            "http_method": kwargs.get("http_method"),
            "url":         kwargs.get("url"),
            "status_code": kwargs.get("status_code"),
            "auth_method": kwargs.get("auth_method"),
            "severity":    kwargs.get("severity", "info"),
            "details":     kwargs.get("details"),
        }

    def _parse_timestamp(self, ts_raw: Optional[str]) -> Optional[str]:
        if not ts_raw:
            return None
        formats = [
            "%b %d %H:%M:%S",
            "%b  %d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%d/%b/%Y:%H:%M:%S %z",
        ]
        ts_clean = ts_raw.strip()
        for fmt in formats:
            try:
                dt = datetime.strptime(ts_clean[:len(fmt) + 5], fmt)
                return dt.isoformat()
            except Exception:
                continue
        return ts_raw  # return raw if parsing fails
