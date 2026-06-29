export function parseTimestamp(ts) {
  if (ts == null) return null
  if (typeof ts === "object" && !Array.isArray(ts)) {
    const inner = ts["$date"]
    if (inner != null) return parseTimestamp(inner)
    if (ts instanceof Date) return isNaN(ts.getTime()) ? null : ts
    return null
  }
  if (typeof ts === "number") {
    const d = new Date(ts < 1e10 ? ts * 1000 : ts)
    return isNaN(d.getTime()) ? null : d
  }
  if (typeof ts === "string") {
    const s = ts.trim()
    if (/^\d{2}:\d{2}:\d{2}$/.test(s)) return s
    if (/^\d+$/.test(s)) return parseTimestamp(Number(s))
    const d = new Date(s.replace(" ", "T"))
    return isNaN(d.getTime()) ? null : d
  }
  return null
}

export function formatTime(ts) {
  const p = parseTimestamp(ts)
  if (!p) return "—"
  if (typeof p === "string") return p
  return p.toLocaleString("fr-FR", {
    day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false,
  })
}

export function normalizeProtocol(raw) {
  const ALIASES = { ICMP: "ICMP", TCP: "TCP", UDP: "UDP", ARP: "ARP" }
  const proto   = raw ? String(raw).toUpperCase().trim() : "?"
  return ALIASES[proto] ?? proto
}