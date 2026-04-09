"""
Threat Detection Engine – Rule-based heuristics for identifying security threats.
Detects: brute force, port scans, suspicious IPs, abnormal login times, web attacks.
"""

from collections import defaultdict
from datetime import datetime
from typing import Optional
import re

# ─── Known Threat Intelligence (simplified inline lists) ──────────────────────

SUSPICIOUS_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "dirbuster",
    "dirb", "gobuster", "wfuzz", "hydra", "medusa", "metasploit",
    "python-requests/", "go-http-client", "curl/", "wget/",
]

SENSITIVE_URLS = [
    "/admin", "/.env", "/wp-admin", "/phpmyadmin", "/.git",
    "/etc/passwd", "/etc/shadow", "/proc/self", "/../",
    "/../..", "/shell", "/cmd", "/exec", "/eval",
    "select%20", "union%20", "drop%20table", "<script>",
    "javascript:", "onerror=", "onload=",
]

PRIVATE_RANGES = [
    re.compile(r'^10\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^127\.'),
]

BUSINESS_HOURS = range(7, 19)  # 07:00 – 18:59 considered normal

# ─── Thresholds ───────────────────────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD     = 5    # failed logins from one IP within the log window
PORT_SCAN_THRESHOLD       = 10   # distinct ports from one IP
HIGH_VOLUME_REQ_THRESHOLD = 50   # HTTP requests from one IP
SEQUENTIAL_PORT_THRESHOLD = 5    # sequential port numbers = likely scan


def is_private_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    return any(p.match(ip) for p in PRIVATE_RANGES)


class ThreatDetector:

    def detect(self, events: list) -> dict:
        """
        Run all detection rules against a list of parsed events.
        Returns a structured threat summary.
        """
        threats = []
        stats = self._compute_stats(events)

        threats += self._detect_brute_force(stats, events)
        threats += self._detect_port_scan(stats, events)
        threats += self._detect_abnormal_login_times(events)
        threats += self._detect_web_attacks(events)
        threats += self._detect_high_volume_requests(stats)
        threats += self._detect_repeated_invalid_users(stats)
        threats += self._detect_successful_after_failures(stats, events)

        severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        threats.sort(key=lambda t: severity_order.get(t["severity"], 99))

        overall_severity = "low"
        if any(t["severity"] == "high" for t in threats):
            overall_severity = "high"
        elif any(t["severity"] == "medium" for t in threats):
            overall_severity = "medium"

        severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for t in threats:
            severity_counts[t["severity"]] = severity_counts.get(t["severity"], 0) + 1

        return {
            "total_events":      len(events),
            "total_threats":     len(threats),
            "overall_severity":  overall_severity,
            "severity_counts":   severity_counts,
            "threats":           threats,
            "suspicious_ips":    list(stats["suspicious_ips"]),
            "top_ips":           self._top_n(stats["ip_event_count"], 10),
            "top_users":         self._top_n(stats["user_fail_count"], 5),
            "event_type_counts": dict(stats["event_type_counts"]),
            "timeline":          self._build_timeline(events),
        }

    # ─── Stats Computation ──────────────────────────────────────────────────────

    def _compute_stats(self, events: list) -> dict:
        ip_fail_count     = defaultdict(int)
        ip_event_count    = defaultdict(int)
        ip_ports          = defaultdict(set)
        ip_success_count  = defaultdict(int)
        user_fail_count   = defaultdict(int)
        event_type_counts = defaultdict(int)
        suspicious_ips    = set()
        ip_urls           = defaultdict(list)

        for e in events:
            ip = e.get("source_ip")
            et = e.get("event_type", "")
            user = e.get("username")

            if ip:
                ip_event_count[ip] += 1

            event_type_counts[et] += 1

            if et in ("ssh_failed_login", "auth_failure"):
                if ip:
                    ip_fail_count[ip] += 1
                if user:
                    user_fail_count[user] += 1

            if et == "ssh_successful_login":
                if ip:
                    ip_success_count[ip] += 1

            if et == "firewall_block" and ip:
                dest_port = e.get("dest_port")
                if dest_port:
                    ip_ports[ip].add(dest_port)

            if et == "http_request":
                url = e.get("url", "")
                if ip:
                    ip_urls[ip].append(url)
                    # check user-agent in details
                    details = (e.get("details") or "").lower()
                    for agent in SUSPICIOUS_USER_AGENTS:
                        if agent in details:
                            suspicious_ips.add(ip)

        # Mark brute-force IPs as suspicious
        for ip, cnt in ip_fail_count.items():
            if cnt >= BRUTE_FORCE_THRESHOLD:
                suspicious_ips.add(ip)

        return {
            "ip_fail_count":     ip_fail_count,
            "ip_event_count":    ip_event_count,
            "ip_ports":          ip_ports,
            "ip_success_count":  ip_success_count,
            "user_fail_count":   user_fail_count,
            "event_type_counts": event_type_counts,
            "suspicious_ips":    suspicious_ips,
            "ip_urls":           ip_urls,
        }

    # ─── Detection Rules ───────────────────────────────────────────────────────

    def _detect_brute_force(self, stats: dict, events: list) -> list:
        threats = []
        for ip, cnt in stats["ip_fail_count"].items():
            if cnt >= BRUTE_FORCE_THRESHOLD:
                # Find associated usernames
                users = {e.get("username") for e in events
                         if e.get("source_ip") == ip and e.get("username")}
                # Determine method
                methods = {e.get("auth_method") for e in events
                           if e.get("source_ip") == ip and e.get("auth_method")}
                users_tried = len(users)
                label = "SSH Brute Force Attack" if "ssh_failed_login" in str(stats["event_type_counts"]) \
                    else "Credential Stuffing Attack"
                threats.append({
                    "threat_id":    f"BRF-{ip.replace('.', '')}",
                    "type":         "brute_force",
                    "label":        label,
                    "severity":     "high",
                    "source_ip":    ip,
                    "description":  f"{cnt} failed login attempts from {ip}. "
                                    f"Targeted {users_tried} username(s): {', '.join(list(users)[:5])}. "
                                    f"Auth methods used: {', '.join(methods) or 'unknown'}.",
                    "count":        cnt,
                    "usernames":    list(users),
                    "mitre_tactic": "Credential Access",
                    "mitre_technique": "T1110 – Brute Force",
                })
        return threats

    def _detect_port_scan(self, stats: dict, events: list) -> list:
        threats = []
        for ip, ports in stats["ip_ports"].items():
            if len(ports) >= PORT_SCAN_THRESHOLD:
                sorted_ports = sorted(ports)
                # Check for sequential ports
                sequential = sum(
                    1 for i in range(len(sorted_ports) - 1)
                    if sorted_ports[i + 1] - sorted_ports[i] == 1
                )
                scan_type = "Sequential Port Scan" if sequential >= SEQUENTIAL_PORT_THRESHOLD \
                    else "Port Scan"
                threats.append({
                    "threat_id":    f"SCAN-{ip.replace('.', '')}",
                    "type":         "port_scan",
                    "label":        scan_type,
                    "severity":     "high",
                    "source_ip":    ip,
                    "description":  f"IP {ip} probed {len(ports)} distinct ports. "
                                    f"Ports: {sorted_ports[:20]}. "
                                    f"{'Sequential scanning pattern detected.' if sequential >= SEQUENTIAL_PORT_THRESHOLD else ''}",
                    "count":        len(ports),
                    "ports":        sorted_ports[:50],
                    "mitre_tactic": "Reconnaissance",
                    "mitre_technique": "T1046 – Network Service Discovery",
                })
        return threats

    def _detect_abnormal_login_times(self, events: list) -> list:
        threats = []
        seen_ips = set()
        for e in events:
            if e.get("event_type") not in ("ssh_successful_login", "auth_success"):
                continue
            ts = e.get("timestamp") or e.get("timestamp_raw")
            if not ts:
                continue
            hour = self._extract_hour(ts)
            if hour is None:
                continue
            if hour not in BUSINESS_HOURS:
                ip = e.get("source_ip", "unknown")
                user = e.get("username", "unknown")
                key = f"{ip}:{user}"
                if key in seen_ips:
                    continue
                seen_ips.add(key)
                threats.append({
                    "threat_id":    f"TIME-{ip.replace('.', '')}-{hour}",
                    "type":         "abnormal_login_time",
                    "label":        "Suspicious Login Outside Business Hours",
                    "severity":     "medium",
                    "source_ip":    ip,
                    "description":  f"Successful login by '{user}' from {ip} at {hour:02d}:xx "
                                    f"(outside normal business hours 07:00-18:59).",
                    "username":     user,
                    "hour":         hour,
                    "mitre_tactic": "Initial Access",
                    "mitre_technique": "T1078 – Valid Accounts",
                })
        return threats

    def _detect_web_attacks(self, events: list) -> list:
        threats = []
        web_events = [e for e in events if e.get("event_type") == "http_request"]
        ip_malicious: dict = defaultdict(list)

        for e in web_events:
            url = (e.get("url") or "").lower()
            details = (e.get("details") or "").lower()
            ip = e.get("source_ip")
            if not ip:
                continue

            for sig in SENSITIVE_URLS:
                if sig.lower() in url or sig.lower() in details:
                    ip_malicious[ip].append({
                        "url": e.get("url"),
                        "sig": sig,
                        "status": e.get("status_code"),
                    })
                    break  # one match per event is enough

        for ip, hits in ip_malicious.items():
            sigs_found = list({h["sig"] for h in hits})
            is_sqli = any(s in str(sigs_found) for s in ("select%20", "union%20", "drop%20"))
            is_xss  = any(s in str(sigs_found) for s in ("<script>", "onerror=", "javascript:"))
            is_lfi  = any(s in str(sigs_found) for s in ("/../", "/etc/passwd", "/proc/self"))

            attack_type = []
            mitre = "T1190 – Exploit Public-Facing Application"
            if is_sqli: attack_type.append("SQL Injection")
            if is_xss:  attack_type.append("XSS")
            if is_lfi:  attack_type.append("Path Traversal / LFI")
            if not attack_type: attack_type.append("Web Attack")

            threats.append({
                "threat_id":    f"WEB-{ip.replace('.', '')}",
                "type":         "web_attack",
                "label":        " + ".join(attack_type),
                "severity":     "high",
                "source_ip":    ip,
                "description":  f"IP {ip} sent {len(hits)} suspicious HTTP request(s). "
                                f"Attack signatures: {', '.join(sigs_found[:5])}. "
                                f"Attack types identified: {', '.join(attack_type)}.",
                "count":        len(hits),
                "urls":         [h["url"] for h in hits[:10]],
                "mitre_tactic": "Initial Access",
                "mitre_technique": mitre,
            })
        return threats

    def _detect_high_volume_requests(self, stats: dict) -> list:
        threats = []
        for ip, cnt in stats["ip_event_count"].items():
            if cnt >= HIGH_VOLUME_REQ_THRESHOLD and not is_private_ip(ip):
                threats.append({
                    "threat_id":    f"VOL-{ip.replace('.', '')}",
                    "type":         "high_volume",
                    "label":        "High Volume Requests (Possible DDoS / Scraping)",
                    "severity":     "medium",
                    "source_ip":    ip,
                    "description":  f"IP {ip} generated {cnt} events in the log window, "
                                    "exceeding the high-volume threshold.",
                    "count":        cnt,
                    "mitre_tactic": "Impact",
                    "mitre_technique": "T1499 – Endpoint Denial of Service",
                })
        return threats

    def _detect_repeated_invalid_users(self, stats: dict) -> list:
        threats = []
        for user, cnt in stats["user_fail_count"].items():
            if cnt >= BRUTE_FORCE_THRESHOLD and user in ("root", "admin", "administrator", "test", "guest"):
                threats.append({
                    "threat_id":    f"PRIV-{user}-{cnt}",
                    "type":         "privileged_account_attack",
                    "label":        f"Repeated Attack on Privileged Account '{user}'",
                    "severity":     "high",
                    "source_ip":    None,
                    "description":  f"Privileged username '{user}' experienced {cnt} failed authentication attempts. "
                                    "This indicates a targeted attack on a high-value account.",
                    "count":        cnt,
                    "username":     user,
                    "mitre_tactic": "Credential Access",
                    "mitre_technique": "T1110.001 – Password Guessing",
                })
        return threats

    def _detect_successful_after_failures(self, stats: dict, events: list) -> list:
        """Detect if a successful login followed multiple failures from the same IP."""
        threats = []
        success_ips = {e.get("source_ip") for e in events
                       if e.get("event_type") == "ssh_successful_login" and e.get("source_ip")}

        for ip in success_ips:
            fail_cnt = stats["ip_fail_count"].get(ip, 0)
            if fail_cnt >= 3:
                user = next(
                    (e.get("username") for e in events
                     if e.get("source_ip") == ip and e.get("event_type") == "ssh_successful_login"),
                    "unknown"
                )
                threats.append({
                    "threat_id":    f"BRF-WIN-{ip.replace('.', '')}",
                    "type":         "brute_force_success",
                    "label":        "⚠️ Brute Force Succeeded – Account Compromised",
                    "severity":     "high",
                    "source_ip":    ip,
                    "description":  f"IP {ip} had {fail_cnt} failed login attempts followed by a "
                                    f"SUCCESSFUL login as '{user}'. Account may be compromised.",
                    "count":        fail_cnt,
                    "username":     user,
                    "mitre_tactic": "Credential Access",
                    "mitre_technique": "T1110 – Brute Force (Successful)",
                })
        return threats

    # ─── Helpers ────────────────────────────────────────────────────────────────

    def _extract_hour(self, ts: str) -> Optional[int]:
        ts = str(ts)
        # ISO format: 2024-01-15T02:34:56
        m = re.search(r'T(\d{2}):', ts)
        if m:
            return int(m.group(1))
        # HH:MM:SS
        m = re.search(r'\b(\d{2}):\d{2}:\d{2}\b', ts)
        if m:
            return int(m.group(1))
        return None

    def _top_n(self, counter: dict, n: int) -> list:
        return sorted(
            [{"key": k, "count": v} for k, v in counter.items()],
            key=lambda x: x["count"], reverse=True
        )[:n]

    def _build_timeline(self, events: list) -> list:
        """Group events by hour for a timeline chart."""
        hour_counts: dict = defaultdict(lambda: {"total": 0, "threats": 0, "info": 0})
        for e in events:
            ts = e.get("timestamp") or e.get("timestamp_raw") or ""
            m = re.search(r'(\d{4}-\d{2}-\d{2})[T ](\d{2}):', str(ts))
            if m:
                bucket = f"{m.group(1)} {m.group(2)}:00"
            else:
                sm = re.search(r'(\d{2}:\d{2}):', str(ts))
                bucket = sm.group(1) if sm else "unknown"

            hour_counts[bucket]["total"] += 1
            if e.get("severity") in ("high", "medium"):
                hour_counts[bucket]["threats"] += 1
            else:
                hour_counts[bucket]["info"] += 1

        return [
            {"time": k, **v}
            for k, v in sorted(hour_counts.items())
        ]
