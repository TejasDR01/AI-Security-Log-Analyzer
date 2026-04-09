"""
AI Security Log Analyzer – FastAPI Backend
SOC Assistant powered by LLM
"""

import os
import time
import uuid
import asyncio
from pathlib import Path
from typing import Optional
from collections import defaultdict

from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import uvicorn

from log_parser import LogParser
from threat_detector import ThreatDetector
from llm_analyzer import LLMAnalyzer

# ─── Configuration ────────────────────────────────────────────────────────────

MAX_FILE_SIZE_MB = 10
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
ALLOWED_EXTENSIONS = {".log", ".txt", ".json"}
RATE_LIMIT_REQUESTS = 30
RATE_LIMIT_WINDOW = 60  # seconds

# ─── App Init ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="AI Security Log Analyzer API",
    description="LLM-powered SOC Assistant for security log analysis",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Rate Limiter ─────────────────────────────────────────────────────────────

request_counts: dict = defaultdict(list)

async def rate_limit_check(request: Request):
    client_ip = request.client.host
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW

    # Clean old requests
    request_counts[client_ip] = [
        t for t in request_counts[client_ip] if t > window_start
    ]

    if len(request_counts[client_ip]) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Max {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW}s."
        )

    request_counts[client_ip].append(now)

# ─── Request Models ────────────────────────────────────────────────────────────

class LogTextRequest(BaseModel):
    log_text: str
    log_type: Optional[str] = "auto"

    @validator("log_text")
    def validate_log_text(cls, v):
        if not v or not v.strip():
            raise ValueError("Log text cannot be empty")
        if len(v) > MAX_FILE_SIZE_BYTES:
            raise ValueError(f"Log text exceeds {MAX_FILE_SIZE_MB}MB limit")
        # Basic sanitization – strip null bytes
        v = v.replace("\x00", "")
        return v

    @validator("log_type")
    def validate_log_type(cls, v):
        allowed = {"auto", "ssh", "auth", "web", "firewall", "application", "json"}
        if v not in allowed:
            raise ValueError(f"log_type must be one of: {allowed}")
        return v

class AnalyzeRequest(BaseModel):
    session_id: str
    include_llm: Optional[bool] = True

# ─── In-Memory Session Store ───────────────────────────────────────────────────

sessions: dict = {}

# ─── Services ─────────────────────────────────────────────────────────────────

parser = LogParser()
detector = ThreatDetector()
analyzer = LLMAnalyzer()

# ─── Helpers ──────────────────────────────────────────────────────────────────

def sanitize_filename(filename: str) -> str:
    """Strip path traversal and dangerous chars from filenames."""
    return Path(filename).name.replace("..", "").replace("/", "").replace("\\", "")

def validate_file(file: UploadFile) -> None:
    """Validate uploaded file type and name."""
    safe_name = sanitize_filename(file.filename or "")
    ext = Path(safe_name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type '{ext}'. Allowed: {ALLOWED_EXTENSIONS}"
        )

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    return {"status": "ok", "version": "1.0.0"}


@app.post("/upload_logs", dependencies=[Depends(rate_limit_check)])
async def upload_logs(
    file: UploadFile = File(...),
    log_type: Optional[str] = "auto"
):
    """
    Upload a log file (.log, .txt, .json) for analysis.
    Returns a session_id for subsequent analysis calls.
    """
    validate_file(file)

    content = await file.read(MAX_FILE_SIZE_BYTES + 1)
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds {MAX_FILE_SIZE_MB}MB limit"
        )

    try:
        log_text = content.decode("utf-8", errors="replace").replace("\x00", "")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode file as UTF-8")

    session_id = str(uuid.uuid4())
    parsed = parser.parse(log_text, log_type=log_type)

    sessions[session_id] = {
        "raw": log_text[:5000],  # store truncated raw for display
        "parsed": parsed,
        "filename": sanitize_filename(file.filename or "upload"),
        "log_type": log_type,
        "threats": None,
        "llm_analysis": None,
    }

    return {
        "session_id": session_id,
        "filename": sanitize_filename(file.filename or ""),
        "total_lines": parsed["total_lines"],
        "parsed_events": len(parsed["events"]),
        "log_type_detected": parsed["detected_type"],
    }


@app.post("/parse_text", dependencies=[Depends(rate_limit_check)])
async def parse_text_logs(body: LogTextRequest):
    """Accept raw pasted log text and return a session_id."""
    parsed = parser.parse(body.log_text, log_type=body.log_type)
    session_id = str(uuid.uuid4())

    sessions[session_id] = {
        "raw": body.log_text[:5000],
        "parsed": parsed,
        "filename": "pasted_logs",
        "log_type": body.log_type,
        "threats": None,
        "llm_analysis": None,
    }

    return {
        "session_id": session_id,
        "total_lines": parsed["total_lines"],
        "parsed_events": len(parsed["events"]),
        "log_type_detected": parsed["detected_type"],
    }


@app.post("/analyze_logs", dependencies=[Depends(rate_limit_check)])
async def analyze_logs(body: AnalyzeRequest):
    """
    Run threat detection + optional LLM analysis on a session.
    """
    session = sessions.get(body.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    parsed = session["parsed"]

    # Rule-based threat detection
    threats = detector.detect(parsed["events"])
    session["threats"] = threats

    result = {
        "session_id": body.session_id,
        "threat_summary": threats,
        "llm_analysis": None,
    }

    # LLM analysis (optional)
    if body.include_llm:
        try:
            llm_result = await analyzer.analyze(parsed["events"], threats)
            session["llm_analysis"] = llm_result
            result["llm_analysis"] = llm_result
        except Exception as e:
            result["llm_error"] = str(e)

    return result


@app.get("/get_threat_summary/{session_id}", dependencies=[Depends(rate_limit_check)])
async def get_threat_summary(session_id: str):
    """Return cached threat detection results for a session."""
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session["threats"] is None:
        raise HTTPException(status_code=400, detail="Logs not yet analyzed. Call /analyze_logs first.")

    return {
        "session_id": session_id,
        "filename": session["filename"],
        "threat_summary": session["threats"],
        "parsed_events": session["parsed"]["events"][:100],  # cap for response size
    }


@app.get("/get_llm_analysis/{session_id}", dependencies=[Depends(rate_limit_check)])
async def get_llm_analysis(session_id: str):
    """Return cached LLM analysis results for a session."""
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session["llm_analysis"] is None:
        raise HTTPException(status_code=400, detail="LLM analysis not yet run.")

    return {
        "session_id": session_id,
        "llm_analysis": session["llm_analysis"],
    }


@app.post("/generate_soc_report/{session_id}", dependencies=[Depends(rate_limit_check)])
async def generate_soc_report(session_id: str):
    """
    Generate a full SOC Incident Report with MITRE ATT&CK mapping.
    """
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session["threats"] is None:
        threats = detector.detect(session["parsed"]["events"])
        session["threats"] = threats

    try:
        report = await analyzer.generate_soc_report(
            events=session["parsed"]["events"],
            threats=session["threats"],
            filename=session["filename"],
        )
        return {"session_id": session_id, "report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@app.get("/sample_logs")
async def list_sample_logs():
    """Return available sample log dataset names."""
    return {
        "samples": [
            {"id": "ssh_bruteforce", "label": "SSH Brute Force Attack", "type": "ssh"},
            {"id": "web_attack", "label": "Web Server Attack (SQL Injection + DirTraversal)", "type": "web"},
            {"id": "firewall_scan", "label": "Port Scan + Firewall Blocks", "type": "firewall"},
            {"id": "normal_auth", "label": "Normal User Logins", "type": "auth"},
            {"id": "mixed_threats", "label": "Mixed Threat Scenario", "type": "auto"},
        ]
    }


@app.get("/sample_logs/{sample_id}")
async def get_sample_log(sample_id: str, request: Request):
    """Load and pre-parse a sample log dataset."""
    await rate_limit_check(request)

    datasets_dir = Path(__file__).parent.parent / "datasets"
    file_map = {
        "ssh_bruteforce": "ssh_bruteforce.log",
        "web_attack": "web_attack.log",
        "firewall_scan": "firewall.log",
        "normal_auth": "normal_auth.log",
        "mixed_threats": "mixed_threats.log",
    }

    filename = file_map.get(sample_id)
    if not filename:
        raise HTTPException(status_code=404, detail="Sample not found")

    filepath = datasets_dir / filename
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Sample file missing from server")

    log_text = filepath.read_text(encoding="utf-8")
    parsed = parser.parse(log_text, log_type="auto")
    session_id = str(uuid.uuid4())

    sessions[session_id] = {
        "raw": log_text[:5000],
        "parsed": parsed,
        "filename": filename,
        "log_type": "auto",
        "threats": None,
        "llm_analysis": None,
    }

    return {
        "session_id": session_id,
        "sample_id": sample_id,
        "total_lines": parsed["total_lines"],
        "parsed_events": len(parsed["events"]),
        "raw_preview": log_text[:800],
    }


# ─── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
