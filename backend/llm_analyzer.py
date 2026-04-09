"""
LLM Analyzer – Abstraction layer for LLM-based log analysis.
Supports: Anthropic Claude (default), OpenAI, and local Ollama models.
Switch provider via LLM_PROVIDER env variable.
"""

import os
import json
import asyncio
import httpx
from datetime import datetime
from typing import Optional

# ─── Provider Config ──────────────────────────────────────────────────────────

LLM_PROVIDER   = os.getenv("LLM_PROVIDER", "anthropic")          # anthropic | openai | ollama
ANTHROPIC_KEY  = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_KEY     = os.getenv("OPENAI_API_KEY", "")
OLLAMA_HOST    = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL", "llama3")
MODEL_NAME     = os.getenv("LLM_MODEL", "claude-haiku-4-5-20251001")  # override model name

TIMEOUT        = 60  # seconds

# ─── Prompt Templates ─────────────────────────────────────────────────────────

ANALYSIS_SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst with expertise in 
cybersecurity threat detection, log analysis, and incident response. 
Analyze security logs with precision, clarity, and actionable insights.
Always structure your responses as valid JSON. Be concise but thorough.
Use real-world cybersecurity terminology and MITRE ATT&CK framework references where appropriate."""

SOC_REPORT_SYSTEM_PROMPT = """You are a senior SOC analyst writing a formal incident report. 
Generate professional, structured incident reports following industry standards.
Include MITRE ATT&CK mappings, affected systems, timeline, and remediation steps.
Return ONLY valid JSON. Do not include markdown fences or explanatory text outside the JSON object."""


def _summarize_events(events: list, max_events: int = 50) -> str:
    """Create a compact event summary for the LLM prompt."""
    sample = events[:max_events]
    lines = []
    for e in sample:
        parts = [
            f"[{e.get('event_type', 'event')}]",
            f"ts={e.get('timestamp_raw') or e.get('timestamp') or 'N/A'}",
        ]
        if e.get("source_ip"):
            parts.append(f"ip={e['source_ip']}")
        if e.get("username"):
            parts.append(f"user={e['username']}")
        if e.get("status_code"):
            parts.append(f"status={e['status_code']}")
        if e.get("url"):
            parts.append(f"url={e['url'][:80]}")
        if e.get("details"):
            parts.append(f"detail={e['details'][:100]}")
        lines.append(" | ".join(parts))
    return "\n".join(lines)


def _summarize_threats(threats: dict) -> str:
    summary = [
        f"Total Events: {threats.get('total_events', 0)}",
        f"Total Threats Detected: {threats.get('total_threats', 0)}",
        f"Overall Severity: {threats.get('overall_severity', 'unknown').upper()}",
        f"Suspicious IPs: {', '.join(threats.get('suspicious_ips', [])[:10]) or 'none'}",
        "",
        "Detected Threats:",
    ]
    for t in threats.get("threats", []):
        summary.append(f"  - [{t['severity'].upper()}] {t['label']}: {t['description'][:200]}")
    return "\n".join(summary)


# ─── Analyzer Class ────────────────────────────────────────────────────────────

class LLMAnalyzer:

    async def analyze(self, events: list, threats: dict) -> dict:
        """
        Run LLM analysis on parsed events and detected threats.
        Returns structured AI findings.
        """
        event_summary   = _summarize_events(events, max_events=60)
        threat_summary  = _summarize_threats(threats)

        prompt = f"""Analyze the following security log data and detected threats. 
Return a JSON object with these exact keys:

{{
  "executive_summary": "2-3 sentence high-level summary for management",
  "threat_narrative": "Detailed paragraph explaining what happened, attack progression, and attacker's likely objective",
  "severity_score": <integer 0-100>,
  "severity_label": "<Low|Medium|High|Critical>",
  "key_findings": ["finding 1", "finding 2", ...],
  "affected_systems": ["system 1", "system 2", ...],
  "attacker_behavior": "Analysis of attacker TTPs and methodology",
  "immediate_actions": ["action 1", "action 2", ...],
  "long_term_recommendations": ["recommendation 1", ...],
  "false_positive_likelihood": "<Low|Medium|High>",
  "confidence": "<Low|Medium|High>"
}}

=== PARSED LOG EVENTS (sample) ===
{event_summary}

=== RULE-BASED THREAT DETECTION RESULTS ===
{threat_summary}

Return ONLY the JSON object. No markdown, no explanations outside the JSON."""

        raw = await self._call_llm(ANALYSIS_SYSTEM_PROMPT, prompt)
        return self._safe_parse(raw)

    async def generate_soc_report(self, events: list, threats: dict, filename: str) -> dict:
        """Generate a full formal SOC Incident Report."""
        event_summary  = _summarize_events(events, max_events=80)
        threat_summary = _summarize_threats(threats)
        report_date    = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        prompt = f"""Generate a formal SOC Incident Report for the following security event data.
Return a single JSON object with these keys:

{{
  "report_metadata": {{
    "report_id": "INC-<random 6 digit number>",
    "date": "{report_date}",
    "analyst": "AI SOC Assistant",
    "source_file": "{filename}",
    "classification": "CONFIDENTIAL",
    "status": "OPEN"
  }},
  "incident_overview": {{
    "title": "<descriptive incident title>",
    "severity": "<Low|Medium|High|Critical>",
    "severity_score": <0-100>,
    "incident_type": "<e.g., Brute Force Attack, Web Application Attack>",
    "attack_vector": "<e.g., Network, Web Application, Remote Services>",
    "summary": "<2-3 sentence executive summary>"
  }},
  "timeline": [
    {{"time": "HH:MM", "event": "description of what happened at this time"}}
  ],
  "attack_analysis": {{
    "initial_access": "how attacker gained or attempted access",
    "techniques_used": ["technique 1", "technique 2"],
    "objectives": "inferred attacker goals",
    "sophistication": "<Low|Medium|High>",
    "tools_likely_used": ["tool 1", "tool 2"]
  }},
  "affected_assets": [
    {{"asset": "server/system name", "impact": "what was affected", "status": "Compromised|At Risk|Monitored"}}
  ],
  "indicators_of_compromise": [
    {{"type": "IP|URL|Hash|User", "value": "indicator value", "context": "why it's suspicious"}}
  ],
  "mitre_attack_mapping": [
    {{
      "tactic": "MITRE tactic name",
      "technique_id": "T1xxx",
      "technique_name": "technique name",
      "observed_behavior": "what was observed"
    }}
  ],
  "remediation": {{
    "immediate_actions": [
      {{"priority": "Critical|High|Medium", "action": "action description", "owner": "IT/SOC/Mgmt"}}
    ],
    "short_term": ["action within 24-72 hours"],
    "long_term": ["strategic improvements"],
    "lessons_learned": "key takeaways"
  }},
  "analyst_notes": "Additional context, caveats, and recommendations from the AI analyst"
}}

=== LOG EVENTS (sample) ===
{event_summary}

=== DETECTED THREATS ===
{threat_summary}

Return ONLY the JSON object."""

        raw = await self._call_llm(SOC_REPORT_SYSTEM_PROMPT, prompt)
        return self._safe_parse(raw)

    # ─── LLM Call Dispatch ────────────────────────────────────────────────────

    async def _call_llm(self, system: str, user_prompt: str) -> str:
        provider = LLM_PROVIDER.lower()
        if provider == "anthropic":
            return await self._call_anthropic(system, user_prompt)
        elif provider == "openai":
            return await self._call_openai(system, user_prompt)
        elif provider == "ollama":
            return await self._call_ollama(system, user_prompt)
        else:
            raise ValueError(f"Unknown LLM provider: {provider}")

    # ─── Anthropic ────────────────────────────────────────────────────────────

    async def _call_anthropic(self, system: str, user_prompt: str) -> str:
        if not ANTHROPIC_KEY:
            raise RuntimeError("ANTHROPIC_API_KEY not set")

        payload = {
            "model":      MODEL_NAME,
            "max_tokens": 2048,
            "system":     system,
            "messages":   [{"role": "user", "content": user_prompt}],
        }

        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key":         ANTHROPIC_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type":      "application/json",
                },
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["content"][0]["text"]

    # ─── OpenAI ───────────────────────────────────────────────────────────────

    async def _call_openai(self, system: str, user_prompt: str) -> str:
        if not OPENAI_KEY:
            raise RuntimeError("OPENAI_API_KEY not set")

        model = os.getenv("OPENAI_MODEL", "gpt-4o")
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user_prompt},
            ],
            "max_tokens":   2048,
            "temperature":  0.2,
            "response_format": {"type": "json_object"},
        }

        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENAI_KEY}",
                    "Content-Type":  "application/json",
                },
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    # ─── Ollama (local) ───────────────────────────────────────────────────────

    async def _call_ollama(self, system: str, user_prompt: str) -> str:
        full_prompt = f"SYSTEM: {system}\n\nUSER: {user_prompt}"
        payload = {
            "model":  OLLAMA_MODEL,
            "prompt": full_prompt,
            "stream": False,
        }

        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post(
                f"{OLLAMA_HOST}/api/generate",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "")

    # ─── Safe JSON Parse ──────────────────────────────────────────────────────

    def _safe_parse(self, raw: str) -> dict:
        """Attempt to extract and parse JSON from LLM response."""
        if not raw:
            return {"error": "Empty LLM response"}
        # Strip markdown fences if present
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            cleaned = "\n".join(lines[1:])
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            # Try to extract JSON object
            start = cleaned.find("{")
            end   = cleaned.rfind("}") + 1
            if start != -1 and end > start:
                try:
                    return json.loads(cleaned[start:end])
                except Exception:
                    pass

        return {"raw_response": raw, "error": "Could not parse LLM JSON response"}
