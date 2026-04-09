const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function apiFetch(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

export const api = {
  health:        () => apiFetch("/health"),
  sampleList:    () => apiFetch("/sample_logs"),
  loadSample:    (id) => apiFetch(`/sample_logs/${id}`),

  uploadFile: (file, logType = "auto") => {
    const form = new FormData();
    form.append("file", file);
    form.append("log_type", logType);
    return fetch(`${API_BASE}/upload_logs?log_type=${logType}`, {
      method: "POST",
      body: form,
    }).then(async (res) => {
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      return res.json();
    });
  },

  parseText: (logText, logType = "auto") =>
    apiFetch("/parse_text", {
      method: "POST",
      body: JSON.stringify({ log_text: logText, log_type: logType }),
    }),

  analyze: (sessionId, includeLlm = true) =>
    apiFetch("/analyze_logs", {
      method: "POST",
      body: JSON.stringify({ session_id: sessionId, include_llm: includeLlm }),
    }),

  getThreatSummary: (sessionId) => apiFetch(`/get_threat_summary/${sessionId}`),
  getLlmAnalysis:  (sessionId) => apiFetch(`/get_llm_analysis/${sessionId}`),

  generateSocReport: (sessionId) =>
    apiFetch(`/generate_soc_report/${sessionId}`, { method: "POST" }),
};
