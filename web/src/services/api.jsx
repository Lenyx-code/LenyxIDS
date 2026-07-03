import axios from "axios"

const BASE_URL = "http://localhost:8000"
const api      = axios.create({ baseURL: BASE_URL })

export const API = {

  // ── Paquets ────────────────────────────────────────────────────
  getPackets: (params = {}) =>
    api.get("/api/packets", { params }),

  // ── Alertes réseau ─────────────────────────────────────────────
  getAlerts: (params = {}) =>
    api.get("/api/alerts", { params }),

  getAlertById: (id) =>
    api.get(`/api/alerts/${id}`),

  updateAlertStatus: (id, status) =>
    api.patch(`/api/alerts/${id}/status`, { status }),

  getAlertsStats: () =>
    api.get("/api/alerts/stats/summary"),

  // ── Rapports forensics ─────────────────────────────────────────
  getReports: () =>
    api.get("/api/reports"),

  getReportById: (id) =>
    api.get(`/api/reports/${id}`),

  getDistinctAttackers: () =>
    api.get("/api/reports/attackers"),

  generateReport: (attacker_ip, victim_ip) =>
    api.post("/api/reports/generate", { attacker_ip, victim_ip }),

  // ── YARA ───────────────────────────────────────────────────────
  yaraScan: (file) => {
    const form = new FormData()
    form.append("file", file)
    return api.post("/api/yara/scan", form, {
      headers: { "Content-Type": "multipart/form-data" },
    })
  },

  yaraHistory: (params = {}) =>
    api.get("/api/yara/history", { params }),

  yaraHistoryById: (id) =>
    api.get(`/api/yara/history/${id}`),

  yaraStats: () =>
    api.get("/api/yara/stats"),

  yaraRulesInfo: () =>
    api.get("/api/yara/rules/info"),

  yaraUpdateRules: () =>
    api.post("/api/yara/rules/update"),

  // ── Monitoring ─────────────────────────────────────────────────
  getMonitoringHosts: () =>
    api.get("/api/monitoring/hosts"),

  getHostHistory: (hostname, limit = 60) =>
    api.get(`/api/monitoring/hosts/${encodeURIComponent(hostname)}/history`, {
      params: { limit },
    }),

  getMonitoringAlerts: (params = {}) =>
    api.get("/api/monitoring/alerts", { params }),

  // ← MANQUAIT : mise à jour statut alertes monitoring
  updateMonitoringAlertStatus: (id, status) =>
    api.patch(`/api/monitoring/alerts/${id}/status`, { status }),

  rebuildBaseline: () =>
    api.post("/api/monitoring/baseline/rebuild"),

  pushMetrics: (metrics) =>
    api.post("/api/monitoring/push", metrics),
  // Monitoring fichiers
getFileChanges: (hostname, params = {}) =>
  api.get(`/api/monitoring/hosts/${encodeURIComponent(hostname)}/file-changes`, { params }),
}

export const SSE_URLS = {
  packets:       `${BASE_URL}/api/stream/packets`,
  alerts:        `${BASE_URL}/api/stream/alerts`,
  alertCount:    `${BASE_URL}/api/stream/count`,
  monitoring:    `${BASE_URL}/api/monitoring/stream`,
  monitorAlerts: `${BASE_URL}/api/monitoring/alerts/stream`,
}