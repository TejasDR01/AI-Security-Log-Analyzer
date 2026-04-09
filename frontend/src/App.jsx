import { useState, useCallback, useRef } from "react";
import {
  Shield, Upload, FileText, Terminal, AlertTriangle, CheckCircle,
  XCircle, Clock, Globe, User, Zap, ChevronRight, BarChart2,
  Activity, Database, Lock, Eye, Download, RefreshCw, Info,
  TrendingUp, AlertOctagon, List, FileSearch, Cpu, Wifi
} from "lucide-react";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, PieChart, Pie, Cell
} from "recharts";
import { api } from "./api.js";

// ─── Constants ────────────────────────────────────────────────────────────────

const SEVERITY_COLORS = { high: "#ff3b5c", medium: "#f5c518", low: "#00d4ff", info: "#8899bb", critical: "#ff0040" };
const SEVERITY_ORDER  = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const SAMPLE_LOGS = [
  { id: "ssh_bruteforce", label: "SSH Brute Force Attack",    icon: Lock,     color: "text-cyber-red" },
  { id: "web_attack",     label: "Web Application Attack",    icon: Globe,    color: "text-cyber-yellow" },
  { id: "firewall_scan",  label: "Port Scan Detection",       icon: Wifi,     color: "text-cyber-accent" },
  { id: "normal_auth",    label: "Normal Activity Baseline",  icon: CheckCircle, color: "text-cyber-green" },
  { id: "mixed_threats",  label: "Mixed Threat Scenario",     icon: AlertOctagon, color: "text-cyber-red" },
];

// ─── Utility Components ───────────────────────────────────────────────────────

function SevBadge({ sev }) {
  const labels = { high: "HIGH", medium: "MED", low: "LOW", info: "INFO", critical: "CRITICAL" };
  return (
    <span className={`badge-${sev === "critical" ? "high" : sev} text-xs font-mono px-2 py-0.5 rounded`}>
      {labels[sev] || sev?.toUpperCase()}
    </span>
  );
}

function Panel({ title, icon: Icon, children, className = "", glow = "" }) {
  return (
    <div className={`bg-cyber-panel rounded border border-cyber-border panel-glow ${glow} ${className}`}>
      {title && (
        <div className="flex items-center gap-2 px-4 py-3 border-b border-cyber-border">
          {Icon && <Icon size={14} className="text-cyber-accent" />}
          <span className="font-display font-semibold text-sm tracking-widest text-cyber-dim uppercase">{title}</span>
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}

function StatCard({ label, value, sub, icon: Icon, color = "text-cyber-accent" }) {
  return (
    <div className="bg-cyber-panel border border-cyber-border rounded p-4 flex items-start gap-3">
      <div className={`mt-0.5 ${color}`}><Icon size={18} /></div>
      <div>
        <div className={`text-2xl font-display font-bold ${color}`}>{value}</div>
        <div className="text-xs text-cyber-dim uppercase tracking-wider">{label}</div>
        {sub && <div className="text-xs text-cyber-dim mt-0.5 mono">{sub}</div>}
      </div>
    </div>
  );
}

function Spinner({ size = 16 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className="animate-spin text-cyber-accent">
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2" fill="none" strokeDasharray="32" strokeDashoffset="8" />
    </svg>
  );
}

// ─── Log Uploader ─────────────────────────────────────────────────────────────

function LogUploader({ onSessionReady, loading, setLoading }) {
  const [mode, setMode]     = useState("sample");   // sample | file | paste
  const [text, setText]     = useState("");
  const [logType, setLogType] = useState("auto");
  const [dragging, setDragging] = useState(false);
  const [error, setError]   = useState("");
  const fileRef = useRef();

  const handleSample = async (id) => {
    try {
      setLoading(true); setError("");
      const res = await api.loadSample(id);
      onSessionReady(res.session_id, res.raw_preview || "");
    } catch (e) { setError(e.message); } finally { setLoading(false); }
  };

  const handleFile = async (file) => {
    if (!file) return;
    setLoading(true); setError("");
    try {
      const res = await api.uploadFile(file, logType);
      onSessionReady(res.session_id, null);
    } catch (e) { setError(e.message); } finally { setLoading(false); }
  };

  const handlePaste = async () => {
    if (!text.trim()) return;
    setLoading(true); setError("");
    try {
      const res = await api.parseText(text, logType);
      onSessionReady(res.session_id, text.slice(0, 600));
    } catch (e) { setError(e.message); } finally { setLoading(false); }
  };

  const onDrop = (e) => {
    e.preventDefault(); setDragging(false);
    handleFile(e.dataTransfer.files[0]);
  };

  return (
    <div className="space-y-4">
      {/* Mode tabs */}
      <div className="flex gap-1 bg-cyber-bg rounded p-1 border border-cyber-border">
        {[["sample", List, "Sample Logs"], ["file", Upload, "Upload File"], ["paste", Terminal, "Paste Text"]].map(([m, Icon, label]) => (
          <button key={m} onClick={() => setMode(m)}
            className={`flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded text-sm font-display font-medium transition-all
              ${mode === m ? "bg-cyber-panel text-cyber-accent border border-cyber-border shadow" : "text-cyber-dim hover:text-cyber-accent"}`}>
            <Icon size={13} />{label}
          </button>
        ))}
      </div>

      {/* Log type selector */}
      <div className="flex items-center gap-3">
        <span className="text-xs text-cyber-dim uppercase tracking-wider">Log Type:</span>
        <div className="flex gap-1 flex-wrap">
          {["auto","ssh","web","firewall","auth","json"].map(t => (
            <button key={t} onClick={() => setLogType(t)}
              className={`text-xs mono px-2 py-1 rounded border transition-all
                ${logType === t ? "border-cyber-accent text-cyber-accent bg-cyber-accent/10" : "border-cyber-border text-cyber-dim hover:border-cyber-dim"}`}>
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* Sample logs */}
      {mode === "sample" && (
        <div className="grid grid-cols-1 gap-2">
          {SAMPLE_LOGS.map(({ id, label, icon: Icon, color }) => (
            <button key={id} onClick={() => handleSample(id)} disabled={loading}
              className="flex items-center gap-3 p-3 bg-cyber-bg border border-cyber-border rounded hover:border-cyber-accent hover:bg-cyber-accent/5 transition-all group disabled:opacity-50">
              <Icon size={15} className={color} />
              <span className="font-display text-sm text-cyber-dim group-hover:text-white transition-colors">{label}</span>
              <ChevronRight size={13} className="ml-auto text-cyber-border group-hover:text-cyber-accent" />
            </button>
          ))}
        </div>
      )}

      {/* File upload */}
      {mode === "file" && (
        <div
          className={`upload-zone border-2 border-dashed border-cyber-border rounded-lg p-8 text-center cursor-pointer ${dragging ? "dragging" : ""}`}
          onClick={() => fileRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}>
          <Upload size={28} className="mx-auto mb-3 text-cyber-dim" />
          <p className="text-sm text-cyber-dim">Drop a log file or <span className="text-cyber-accent">click to browse</span></p>
          <p className="text-xs text-cyber-border mt-1 mono">.log · .txt · .json · max 10MB</p>
          <input ref={fileRef} type="file" accept=".log,.txt,.json" className="hidden"
            onChange={(e) => handleFile(e.target.files[0])} />
        </div>
      )}

      {/* Paste text */}
      {mode === "paste" && (
        <div className="space-y-3">
          <textarea value={text} onChange={(e) => setText(e.target.value)}
            placeholder="Paste log entries here...&#10;&#10;Jan 15 02:03:11 server sshd[3211]: Failed password for root from 1.2.3.4 port 52134 ssh2"
            className="w-full h-48 bg-cyber-bg border border-cyber-border rounded p-3 text-xs mono text-cyber-dim placeholder-cyber-border resize-none focus:outline-none focus:border-cyber-accent" />
          <button onClick={handlePaste} disabled={loading || !text.trim()}
            className="w-full py-2 bg-cyber-accent/10 border border-cyber-accent text-cyber-accent font-display font-semibold text-sm rounded hover:bg-cyber-accent/20 transition-all disabled:opacity-40 flex items-center justify-center gap-2">
            {loading ? <><Spinner size={14} /> Processing…</> : <><Terminal size={14} /> Parse Logs</>}
          </button>
        </div>
      )}

      {error && (
        <div className="flex items-start gap-2 p-3 bg-cyber-red/10 border border-cyber-red/30 rounded text-cyber-red text-sm">
          <XCircle size={15} className="mt-0.5 shrink-0" />{error}
        </div>
      )}
    </div>
  );
}

// ─── Threat Cards ─────────────────────────────────────────────────────────────

function ThreatCard({ threat, idx }) {
  const [open, setOpen] = useState(false);
  const colors = { high: "border-cyber-red/40 bg-cyber-red/5", medium: "border-cyber-yellow/30 bg-cyber-yellow/5", low: "border-cyber-accent/30 bg-cyber-accent/5", info: "border-cyber-border" };

  return (
    <div className={`threat-card border rounded p-3 cursor-pointer transition-all ${colors[threat.severity] || "border-cyber-border"}`}
      style={{ animationDelay: `${idx * 0.06}s` }}
      onClick={() => setOpen(!open)}>
      <div className="flex items-start gap-2">
        <AlertTriangle size={14} className={`mt-0.5 shrink-0 ${threat.severity === "high" ? "text-cyber-red" : threat.severity === "medium" ? "text-cyber-yellow" : "text-cyber-accent"}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-display font-semibold text-sm text-white">{threat.label}</span>
            <SevBadge sev={threat.severity} />
          </div>
          {threat.source_ip && (
            <div className="text-xs mono text-cyber-accent mt-1">SRC: {threat.source_ip}</div>
          )}
          <p className="text-xs text-cyber-dim mt-1 leading-relaxed">{threat.description}</p>
          {open && (
            <div className="mt-2 pt-2 border-t border-cyber-border space-y-1 animate-fade-in">
              {threat.mitre_technique && (
                <span className="mitre-tag"><Shield size={10} />{threat.mitre_technique}</span>
              )}
              {threat.mitre_tactic && (
                <div className="text-xs text-cyber-dim mono">Tactic: {threat.mitre_tactic}</div>
              )}
              {threat.count && (
                <div className="text-xs text-cyber-dim mono">Count: {threat.count}</div>
              )}
              {threat.ports && (
                <div className="text-xs text-cyber-dim mono">Ports: {threat.ports.slice(0,12).join(", ")}{threat.ports.length > 12 ? "…" : ""}</div>
              )}
              {threat.usernames?.length > 0 && (
                <div className="text-xs text-cyber-dim mono">Targets: {threat.usernames.join(", ")}</div>
              )}
            </div>
          )}
        </div>
        <ChevronRight size={13} className={`text-cyber-dim transition-transform shrink-0 ${open ? "rotate-90" : ""}`} />
      </div>
    </div>
  );
}

// ─── AI Analysis Panel ────────────────────────────────────────────────────────

function AiAnalysisPanel({ llm }) {
  if (!llm) return null;
  if (llm.error && !llm.executive_summary) {
    return (
      <div className="p-3 bg-cyber-yellow/10 border border-cyber-yellow/30 rounded text-cyber-yellow text-sm">
        ⚠ LLM analysis unavailable: {llm.error}
      </div>
    );
  }

  const score = llm.severity_score || 0;
  const scoreColor = score >= 70 ? "#ff3b5c" : score >= 40 ? "#f5c518" : "#00d4ff";

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Severity Score */}
      <div className="flex items-center gap-4">
        <div className="relative w-16 h-16 shrink-0">
          <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
            <circle cx="18" cy="18" r="14" fill="none" stroke="#1a2744" strokeWidth="3" />
            <circle cx="18" cy="18" r="14" fill="none" stroke={scoreColor} strokeWidth="3"
              strokeDasharray={`${(score / 100) * 88} 88`} strokeLinecap="round" />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-sm font-display font-bold" style={{ color: scoreColor }}>{score}</span>
          </div>
        </div>
        <div>
          <div className="font-display font-bold text-lg" style={{ color: scoreColor }}>
            {llm.severity_label || "Unknown"}
          </div>
          <div className="text-xs text-cyber-dim">Threat Score · Confidence: {llm.confidence || "–"}</div>
          <div className="text-xs text-cyber-dim">False Positive Risk: {llm.false_positive_likelihood || "–"}</div>
        </div>
      </div>

      {/* Executive Summary */}
      {llm.executive_summary && (
        <div className="p-3 bg-cyber-bg border border-cyber-border rounded">
          <div className="text-xs text-cyber-dim uppercase tracking-wider mb-1 flex items-center gap-1"><Cpu size={10} /> AI Summary</div>
          <p className="text-sm text-white leading-relaxed">{llm.executive_summary}</p>
        </div>
      )}

      {/* Threat Narrative */}
      {llm.threat_narrative && (
        <div>
          <div className="text-xs text-cyber-dim uppercase tracking-wider mb-2 flex items-center gap-1"><Eye size={10} /> Attack Narrative</div>
          <p className="text-sm text-cyber-dim leading-relaxed">{llm.threat_narrative}</p>
        </div>
      )}

      {/* Key Findings */}
      {llm.key_findings?.length > 0 && (
        <div>
          <div className="text-xs text-cyber-dim uppercase tracking-wider mb-2">Key Findings</div>
          <ul className="space-y-1">
            {llm.key_findings.map((f, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-cyber-dim">
                <ChevronRight size={12} className="text-cyber-accent mt-0.5 shrink-0" />{f}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Immediate Actions */}
      {llm.immediate_actions?.length > 0 && (
        <div>
          <div className="text-xs text-cyber-yellow uppercase tracking-wider mb-2 flex items-center gap-1"><Zap size={10} /> Immediate Actions</div>
          <ul className="space-y-1">
            {llm.immediate_actions.map((a, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-cyber-yellow/80">
                <span className="text-cyber-yellow font-mono shrink-0">{i + 1}.</span>{a}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Attacker Behavior */}
      {llm.attacker_behavior && (
        <div className="p-3 bg-cyber-red/5 border border-cyber-red/20 rounded">
          <div className="text-xs text-cyber-red uppercase tracking-wider mb-1 flex items-center gap-1"><AlertTriangle size={10} /> Attacker Behavior</div>
          <p className="text-sm text-cyber-dim leading-relaxed">{llm.attacker_behavior}</p>
        </div>
      )}
    </div>
  );
}

// ─── SOC Report Modal ─────────────────────────────────────────────────────────

function SocReportModal({ report, onClose }) {
  if (!report) return null;
  const r = report;
  const meta = r.report_metadata || {};
  const overview = r.incident_overview || {};
  const mitre = r.mitre_attack_mapping || [];
  const remediation = r.remediation || {};
  const iocs = r.indicators_of_compromise || [];
  const assets = r.affected_assets || [];
  const timeline = r.timeline || [];

  const handlePrint = () => window.print();

  const handleDownload = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `SOC_Report_${meta.report_id || "INC"}.json`; a.click();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/80 backdrop-blur-sm p-4">
      <div className="bg-cyber-panel border border-cyber-border rounded-lg w-full max-w-4xl my-4 shadow-2xl animate-slide-up">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-cyber-border bg-cyber-bg rounded-t-lg">
          <div className="flex items-center gap-3">
            <Shield size={18} className="text-cyber-accent" />
            <div>
              <div className="font-display font-bold text-white text-lg">SOC INCIDENT REPORT</div>
              <div className="text-xs mono text-cyber-dim">{meta.report_id} · {meta.date} · {meta.classification}</div>
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs border border-cyber-border text-cyber-dim rounded hover:border-cyber-accent hover:text-cyber-accent transition-all">
              <Download size={12} /> JSON
            </button>
            <button onClick={onClose}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs border border-cyber-red/30 text-cyber-red rounded hover:bg-cyber-red/10 transition-all">
              <XCircle size={12} /> Close
            </button>
          </div>
        </div>

        <div className="p-6 space-y-6">
          {/* Overview */}
          <div className="soc-report-section">
            <div className="text-xs text-cyber-accent uppercase tracking-wider mb-3 font-display font-semibold">1. Incident Overview</div>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div><span className="text-cyber-dim">Title: </span><span className="text-white font-medium">{overview.title}</span></div>
              <div><span className="text-cyber-dim">Severity: </span><SevBadge sev={(overview.severity || "low").toLowerCase()} /></div>
              <div><span className="text-cyber-dim">Score: </span><span className="text-white mono">{overview.severity_score}/100</span></div>
              <div><span className="text-cyber-dim">Attack Vector: </span><span className="text-white">{overview.attack_vector}</span></div>
              <div className="col-span-2"><span className="text-cyber-dim">Summary: </span><span className="text-cyber-dim">{overview.summary}</span></div>
            </div>
          </div>

          {/* Timeline */}
          {timeline.length > 0 && (
            <div className="soc-report-section">
              <div className="text-xs text-cyber-accent uppercase tracking-wider mb-3 font-display font-semibold">2. Attack Timeline</div>
              <div className="space-y-2">
                {timeline.map((t, i) => (
                  <div key={i} className="flex gap-3 text-sm">
                    <div className="mono text-cyber-accent shrink-0 w-14">{t.time}</div>
                    <div className="text-cyber-dim">{t.event}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* MITRE ATT&CK */}
          {mitre.length > 0 && (
            <div className="soc-report-section">
              <div className="text-xs text-cyber-accent uppercase tracking-wider mb-3 font-display font-semibold">3. MITRE ATT&CK Mapping</div>
              <div className="space-y-3">
                {mitre.map((m, i) => (
                  <div key={i} className="p-3 bg-cyber-bg border border-cyber-border rounded">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="mitre-tag">{m.technique_id}</span>
                      <span className="text-sm text-white font-medium">{m.technique_name}</span>
                      <span className="text-xs text-cyber-dim">· {m.tactic}</span>
                    </div>
                    <p className="text-xs text-cyber-dim">{m.observed_behavior}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* IOCs */}
          {iocs.length > 0 && (
            <div className="soc-report-section">
              <div className="text-xs text-cyber-accent uppercase tracking-wider mb-3 font-display font-semibold">4. Indicators of Compromise</div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-cyber-dim border-b border-cyber-border">
                      <th className="text-left pb-2 mono">TYPE</th>
                      <th className="text-left pb-2 mono">VALUE</th>
                      <th className="text-left pb-2 mono">CONTEXT</th>
                    </tr>
                  </thead>
                  <tbody>
                    {iocs.map((ioc, i) => (
                      <tr key={i} className="border-b border-cyber-border/50 hover:bg-cyber-border/20">
                        <td className="py-1.5 pr-3 text-cyber-yellow">{ioc.type}</td>
                        <td className="py-1.5 pr-3 mono text-cyber-accent">{ioc.value}</td>
                        <td className="py-1.5 text-cyber-dim">{ioc.context}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Affected Assets */}
          {assets.length > 0 && (
            <div className="soc-report-section">
              <div className="text-xs text-cyber-accent uppercase tracking-wider mb-3 font-display font-semibold">5. Affected Assets</div>
              <div className="space-y-2">
                {assets.map((a, i) => (
                  <div key={i} className="flex items-start gap-3 text-sm">
                    <Database size={12} className="text-cyber-dim mt-0.5 shrink-0" />
                    <div>
                      <span className="text-white">{a.asset}</span>
                      <span className={`ml-2 text-xs mono ${a.status === "Compromised" ? "text-cyber-red" : a.status === "At Risk" ? "text-cyber-yellow" : "text-cyber-accent"}`}>
                        [{a.status}]
                      </span>
                      <div className="text-cyber-dim text-xs">{a.impact}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Remediation */}
          <div className="soc-report-section">
            <div className="text-xs text-cyber-accent uppercase tracking-wider mb-3 font-display font-semibold">6. Remediation Plan</div>
            {remediation.immediate_actions?.length > 0 && (
              <div className="mb-3">
                <div className="text-xs text-cyber-yellow mb-2">Immediate Actions</div>
                {remediation.immediate_actions.map((a, i) => (
                  <div key={i} className="flex items-start gap-2 text-sm mb-1.5">
                    <span className={`text-xs font-mono shrink-0 px-1 rounded ${a.priority === "Critical" ? "bg-cyber-red/20 text-cyber-red" : a.priority === "High" ? "bg-cyber-yellow/20 text-cyber-yellow" : "bg-cyber-accent/10 text-cyber-accent"}`}>
                      {a.priority}
                    </span>
                    <span className="text-cyber-dim">{a.action}</span>
                    {a.owner && <span className="text-xs text-cyber-border mono ml-auto shrink-0">[{a.owner}]</span>}
                  </div>
                ))}
              </div>
            )}
            {remediation.lessons_learned && (
              <div className="p-3 bg-cyber-bg border border-cyber-border rounded">
                <div className="text-xs text-cyber-dim uppercase mb-1">Lessons Learned</div>
                <p className="text-sm text-cyber-dim">{remediation.lessons_learned}</p>
              </div>
            )}
          </div>

          {/* Analyst Notes */}
          {r.analyst_notes && (
            <div className="p-3 bg-cyber-accent/5 border border-cyber-accent/20 rounded">
              <div className="text-xs text-cyber-accent uppercase tracking-wider mb-1 flex items-center gap-1"><Cpu size={10} /> AI Analyst Notes</div>
              <p className="text-sm text-cyber-dim leading-relaxed">{r.analyst_notes}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────

export default function App() {
  const [sessionId, setSessionId]       = useState(null);
  const [rawPreview, setRawPreview]     = useState("");
  const [loading, setLoading]           = useState(false);
  const [analyzing, setAnalyzing]       = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [socReport, setSocReport]       = useState(null);
  const [showReport, setShowReport]     = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [activeTab, setActiveTab]       = useState("threats");
  const [error, setError]               = useState("");

  const handleSessionReady = useCallback((sid, preview) => {
    setSessionId(sid);
    setRawPreview(preview || "");
    setAnalysisResult(null);
    setSocReport(null);
    setError("");
  }, []);

  const runAnalysis = async () => {
    if (!sessionId) return;
    setAnalyzing(true); setError("");
    try {
      const res = await api.analyze(sessionId, true);
      setAnalysisResult(res);
    } catch (e) { setError(e.message); } finally { setAnalyzing(false); }
  };

  const generateReport = async () => {
    if (!sessionId) return;
    setReportLoading(true);
    try {
      const res = await api.generateSocReport(sessionId);
      setSocReport(res.report);
      setShowReport(true);
    } catch (e) { setError(e.message); } finally { setReportLoading(false); }
  };

  const threats   = analysisResult?.threat_summary?.threats || [];
  const summary   = analysisResult?.threat_summary || {};
  const llm       = analysisResult?.llm_analysis || null;
  const timeline  = summary?.timeline || [];
  const suspIps   = summary?.suspicious_ips || [];
  const topIps    = summary?.top_ips || [];
  const sevCounts = summary?.severity_counts || {};

  // Charts data
  const pieData = Object.entries(sevCounts)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ name: k.toUpperCase(), value: v, color: SEVERITY_COLORS[k] }));

  const severityScore = llm?.severity_score || (
    threats.some(t => t.severity === "high") ? 75 :
    threats.some(t => t.severity === "medium") ? 45 : 20
  );

  const scoreColor = severityScore >= 70 ? "#ff3b5c" : severityScore >= 40 ? "#f5c518" : "#00ff9d";

  return (
    <div className="min-h-screen bg-cyber-bg scanline-bg">
      {/* Top bar */}
      <header className="sticky top-0 z-40 bg-cyber-bg/95 backdrop-blur border-b border-cyber-border">
        <div className="max-w-screen-2xl mx-auto px-4 py-3 flex items-center gap-4">
          <div className="flex items-center gap-2.5">
            <div className="relative">
              <Shield size={22} className="text-cyber-accent glow-text-cyan" />
              <span className="absolute -top-1 -right-1 w-2 h-2 bg-cyber-green rounded-full animate-pulse" />
            </div>
            <div>
              <div className="font-display font-bold text-white text-base leading-none">AI Security Log Analyzer</div>
              <div className="text-cyber-dim text-xs mono">LLM-Powered SOC Assistant</div>
            </div>
          </div>

          <div className="ml-auto flex items-center gap-3">
            {sessionId && !analysisResult && (
              <button onClick={runAnalysis} disabled={analyzing}
                className="flex items-center gap-2 px-4 py-2 bg-cyber-accent/10 border border-cyber-accent text-cyber-accent font-display font-semibold text-sm rounded hover:bg-cyber-accent/20 transition-all disabled:opacity-50">
                {analyzing ? <><Spinner size={13} /> Analyzing…</> : <><Zap size={13} /> Run AI Analysis</>}
              </button>
            )}
            {analysisResult && (
              <button onClick={generateReport} disabled={reportLoading}
                className="flex items-center gap-2 px-4 py-2 bg-cyber-red/10 border border-cyber-red/50 text-cyber-red font-display font-semibold text-sm rounded hover:bg-cyber-red/20 transition-all disabled:opacity-50">
                {reportLoading ? <><Spinner size={13} /> Generating…</> : <><FileSearch size={13} /> AI SOC Report</>}
              </button>
            )}
            <div className="flex items-center gap-1.5 px-2 py-1 border border-cyber-green/30 rounded">
              <span className="w-1.5 h-1.5 bg-cyber-green rounded-full animate-pulse" />
              <span className="text-cyber-green text-xs mono">LIVE</span>
            </div>
          </div>
        </div>
        {analyzing && <div className="h-px progress-bar w-full" />}
      </header>

      <main className="max-w-screen-2xl mx-auto px-4 py-6">
        <div className="grid grid-cols-12 gap-4">

          {/* ── Left Sidebar ── */}
          <aside className="col-span-12 xl:col-span-3 space-y-4">
            <Panel title="Log Input" icon={Upload}>
              <LogUploader onSessionReady={handleSessionReady} loading={loading} setLoading={setLoading} />
            </Panel>

            {rawPreview && (
              <Panel title="Log Preview" icon={Terminal}>
                <div className="log-display rounded p-3 max-h-48 overflow-y-auto">
                  {rawPreview.split("\n").map((line, i) => {
                    const cls = line.toLowerCase().includes("fail") || line.toLowerCase().includes("invalid") ? "log-fail"
                      : line.toLowerCase().includes("accept") || line.toLowerCase().includes("allow") ? "log-ok"
                      : line.toLowerCase().includes("block") || line.toLowerCase().includes("warn") ? "log-warn"
                      : "";
                    return <div key={i} className={cls}>{line || " "}</div>;
                  })}
                </div>
              </Panel>
            )}

            {sessionId && !analysisResult && !analyzing && (
              <button onClick={runAnalysis}
                className="w-full py-3 bg-cyber-accent/10 border border-cyber-accent text-cyber-accent font-display font-bold text-sm rounded hover:bg-cyber-accent/20 transition-all flex items-center justify-center gap-2">
                <Zap size={15} /> Analyze with AI
              </button>
            )}
          </aside>

          {/* ── Main Content ── */}
          <div className="col-span-12 xl:col-span-9 space-y-4">
            {error && (
              <div className="flex items-start gap-2 p-3 bg-cyber-red/10 border border-cyber-red/30 rounded text-cyber-red text-sm">
                <XCircle size={15} className="mt-0.5 shrink-0" /> {error}
              </div>
            )}

            {/* Welcome state */}
            {!sessionId && (
              <div className="flex flex-col items-center justify-center min-h-[60vh] text-center space-y-6">
                <div className="relative">
                  <div className="w-24 h-24 rounded-full border border-cyber-border flex items-center justify-center">
                    <Shield size={40} className="text-cyber-accent" style={{ filter: "drop-shadow(0 0 12px rgba(0,212,255,0.5))" }} />
                  </div>
                  <div className="absolute -inset-2 rounded-full border border-cyber-accent/10 animate-ping" style={{ animationDuration: "3s" }} />
                </div>
                <div>
                  <h1 className="font-display font-bold text-3xl text-white mb-2">AI SOC Assistant</h1>
                  <p className="text-cyber-dim max-w-md">Select a sample log, upload a file, or paste log entries to begin AI-powered threat analysis.</p>
                </div>
                <div className="grid grid-cols-3 gap-4 text-sm">
                  {[["SSH Brute Force", Lock, "#ff3b5c"], ["Web Attacks", Globe, "#f5c518"], ["Port Scans", Wifi, "#00d4ff"]].map(([l, Icon, c]) => (
                    <div key={l} className="p-3 bg-cyber-panel border border-cyber-border rounded flex flex-col items-center gap-2">
                      <Icon size={18} style={{ color: c }} />
                      <span className="text-cyber-dim">{l}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Loaded but not analyzed */}
            {sessionId && !analysisResult && !analyzing && (
              <Panel title="Ready to Analyze" icon={Activity} glow="">
                <div className="text-center py-8 space-y-4">
                  <Activity size={32} className="mx-auto text-cyber-accent animate-pulse" />
                  <div>
                    <p className="text-white font-display font-semibold">Logs loaded successfully</p>
                    <p className="text-cyber-dim text-sm mt-1">Click "Run AI Analysis" to detect threats and get LLM insights</p>
                  </div>
                </div>
              </Panel>
            )}

            {/* Analyzing state */}
            {analyzing && (
              <Panel title="AI Analysis in Progress" icon={Cpu}>
                <div className="text-center py-8 space-y-4">
                  <div className="flex justify-center"><Spinner size={36} /></div>
                  <div className="space-y-1">
                    {["Parsing log events…", "Running threat detection rules…", "Querying LLM for insights…"].map((s, i) => (
                      <div key={i} className="text-sm text-cyber-dim flex items-center justify-center gap-2">
                        <CheckCircle size={12} className="text-cyber-green" /> {s}
                      </div>
                    ))}
                  </div>
                </div>
              </Panel>
            )}

            {/* Analysis Results */}
            {analysisResult && (
              <>
                {/* Stat cards row */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <StatCard label="Total Events"   value={summary.total_events || 0} icon={BarChart2} />
                  <StatCard label="Threats Found"  value={summary.total_threats || 0} icon={AlertTriangle}
                    color={summary.total_threats > 0 ? "text-cyber-red" : "text-cyber-green"} />
                  <StatCard label="Suspicious IPs" value={suspIps.length}  icon={Globe} color="text-cyber-yellow" />
                  <StatCard label="Threat Score"   value={`${severityScore}/100`} icon={TrendingUp} color={scoreColor} />
                </div>

                {/* Severity alert banner */}
                {summary.overall_severity === "high" && (
                  <div className="flex items-center gap-3 p-3 bg-cyber-red/10 border border-cyber-red/40 rounded panel-glow-red">
                    <AlertOctagon size={18} className="text-cyber-red shrink-0" />
                    <span className="font-display font-semibold text-cyber-red">HIGH SEVERITY THREATS DETECTED</span>
                    <SevBadge sev="high" />
                  </div>
                )}

                {/* Charts row */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* Timeline */}
                  <div className="md:col-span-2 bg-cyber-panel border border-cyber-border rounded panel-glow p-4">
                    <div className="text-xs text-cyber-dim uppercase tracking-wider mb-3 flex items-center gap-1"><Activity size={11} /> Event Timeline</div>
                    <ResponsiveContainer width="100%" height={140}>
                      <AreaChart data={timeline} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
                        <defs>
                          <linearGradient id="tGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3} />
                            <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                          </linearGradient>
                          <linearGradient id="tGradR" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#ff3b5c" stopOpacity={0.4} />
                            <stop offset="95%" stopColor="#ff3b5c" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid stroke="#1a2744" strokeDasharray="3 3" />
                        <XAxis dataKey="time" tick={{ fill: "#8899bb", fontSize: 10 }} interval="preserveStartEnd" />
                        <YAxis tick={{ fill: "#8899bb", fontSize: 10 }} />
                        <Tooltip contentStyle={{ background: "#0c1220", border: "1px solid #1a2744", borderRadius: 4 }} labelStyle={{ color: "#8899bb" }} />
                        <Area type="monotone" dataKey="info" stroke="#00d4ff" fill="url(#tGrad)" strokeWidth={1.5} />
                        <Area type="monotone" dataKey="threats" stroke="#ff3b5c" fill="url(#tGradR)" strokeWidth={1.5} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>

                  {/* Severity pie */}
                  <div className="bg-cyber-panel border border-cyber-border rounded panel-glow p-4">
                    <div className="text-xs text-cyber-dim uppercase tracking-wider mb-3 flex items-center gap-1"><BarChart2 size={11} /> Severity Mix</div>
                    {pieData.length > 0 ? (
                      <>
                        <ResponsiveContainer width="100%" height={100}>
                          <PieChart>
                            <Pie data={pieData} cx="50%" cy="50%" innerRadius={30} outerRadius={48}
                              dataKey="value" paddingAngle={2}>
                              {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                            </Pie>
                            <Tooltip contentStyle={{ background: "#0c1220", border: "1px solid #1a2744" }} />
                          </PieChart>
                        </ResponsiveContainer>
                        <div className="space-y-1 mt-2">
                          {pieData.map(d => (
                            <div key={d.name} className="flex items-center gap-2 text-xs">
                              <span className="w-2 h-2 rounded-full shrink-0" style={{ background: d.color }} />
                              <span className="text-cyber-dim">{d.name}</span>
                              <span className="ml-auto mono" style={{ color: d.color }}>{d.value}</span>
                            </div>
                          ))}
                        </div>
                      </>
                    ) : (
                      <div className="text-center py-4 text-cyber-dim text-xs">No threat data</div>
                    )}
                  </div>
                </div>

                {/* Main tabs */}
                <div>
                  <div className="flex gap-1 bg-cyber-bg rounded p-1 border border-cyber-border mb-4">
                    {[
                      ["threats", AlertTriangle, "Detected Threats"],
                      ["ai",      Cpu,           "AI Analysis"],
                      ["ips",     Globe,         "Suspicious IPs"],
                      ["events",  List,          "Event Log"],
                    ].map(([t, Icon, label]) => (
                      <button key={t} onClick={() => setActiveTab(t)}
                        className={`flex-1 flex items-center justify-center gap-1.5 py-2 text-xs font-display font-medium rounded transition-all
                          ${activeTab === t ? "bg-cyber-panel text-cyber-accent border border-cyber-border" : "text-cyber-dim hover:text-white"}`}>
                        <Icon size={12} />{label}
                        {t === "threats" && threats.length > 0 && (
                          <span className="ml-1 bg-cyber-red/20 text-cyber-red text-xs px-1 rounded">{threats.length}</span>
                        )}
                      </button>
                    ))}
                  </div>

                  {/* Threats Tab */}
                  {activeTab === "threats" && (
                    <div className="space-y-2">
                      {threats.length === 0 ? (
                        <Panel title="" icon={null} glow="panel-glow-green">
                          <div className="flex items-center gap-3 py-4 justify-center text-cyber-green">
                            <CheckCircle size={18} />
                            <span className="font-display font-semibold">No threats detected in this log sample.</span>
                          </div>
                        </Panel>
                      ) : (
                        threats.map((t, i) => <ThreatCard key={t.threat_id} threat={t} idx={i} />)
                      )}
                    </div>
                  )}

                  {/* AI Tab */}
                  {activeTab === "ai" && (
                    <Panel title="AI Analysis" icon={Cpu}>
                      {llm ? <AiAnalysisPanel llm={llm} /> : (
                        <div className="text-center py-8 text-cyber-dim">
                          <Info size={20} className="mx-auto mb-2 text-cyber-border" />
                          <p className="text-sm">LLM analysis not available. Ensure ANTHROPIC_API_KEY is configured.</p>
                        </div>
                      )}
                    </Panel>
                  )}

                  {/* IPs Tab */}
                  {activeTab === "ips" && (
                    <Panel title="IP Intelligence" icon={Globe}>
                      <div className="space-y-4">
                        {suspIps.length > 0 && (
                          <div>
                            <div className="text-xs text-cyber-red uppercase tracking-wider mb-2">⚠ Suspicious IPs</div>
                            <div className="flex flex-wrap gap-2">
                              {suspIps.map(ip => (
                                <span key={ip} className="mono text-xs px-3 py-1.5 bg-cyber-red/10 border border-cyber-red/30 text-cyber-red rounded">
                                  {ip}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                        <div>
                          <div className="text-xs text-cyber-dim uppercase tracking-wider mb-2">Top Active IPs</div>
                          {topIps.length > 0 ? (
                            <div className="space-y-2">
                              {topIps.map(({ key: ip, count }) => {
                                const isSusp = suspIps.includes(ip);
                                const pct = Math.round((count / (topIps[0]?.count || 1)) * 100);
                                return (
                                  <div key={ip} className="flex items-center gap-3">
                                    <span className={`mono text-xs w-32 shrink-0 ${isSusp ? "text-cyber-red" : "text-cyber-accent"}`}>{ip}</span>
                                    <div className="flex-1 h-1.5 bg-cyber-bg rounded-full overflow-hidden">
                                      <div className="h-full rounded-full transition-all"
                                        style={{ width: `${pct}%`, background: isSusp ? "#ff3b5c" : "#00d4ff" }} />
                                    </div>
                                    <span className="text-xs text-cyber-dim mono w-8 text-right">{count}</span>
                                    {isSusp && <AlertTriangle size={11} className="text-cyber-red shrink-0" />}
                                  </div>
                                );
                              })}
                            </div>
                          ) : <p className="text-xs text-cyber-dim">No IP data available.</p>}
                        </div>
                      </div>
                    </Panel>
                  )}

                  {/* Events Tab */}
                  {activeTab === "events" && (
                    <Panel title="Parsed Events" icon={List}>
                      <div className="log-display rounded p-3 max-h-96 overflow-y-auto space-y-0.5">
                        {(analysisResult?.threat_summary?.parsed_events || []).slice(0, 100).map((e, i) => (
                          <div key={i} className={`flex gap-2 py-0.5 border-b border-cyber-border/30 ${e.severity === "high" || e.severity === "medium" ? "log-fail" : e.severity === "info" && e.event_type?.includes("success") ? "log-ok" : ""}`}>
                            <span className="text-cyber-border shrink-0 w-8 text-right">{e.line_num}</span>
                            <span className={`shrink-0 ${e.severity === "high" ? "text-cyber-red" : e.severity === "medium" ? "text-cyber-yellow" : "text-cyber-dim"}`}>[{(e.severity || "info").toUpperCase()}]</span>
                            <span className="text-cyber-dim/70 shrink-0">{e.event_type}</span>
                            {e.source_ip && <span className="text-cyber-accent">{e.source_ip}</span>}
                            {e.username && <span className="text-cyber-green/80">user:{e.username}</span>}
                            {e.status_code && <span className={e.status_code >= 400 ? "text-cyber-red" : "text-cyber-green/70"}>{e.status_code}</span>}
                          </div>
                        ))}
                      </div>
                    </Panel>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      </main>

      {/* SOC Report Modal */}
      {showReport && socReport && (
        <SocReportModal report={socReport} onClose={() => setShowReport(false)} />
      )}
    </div>
  );
}
