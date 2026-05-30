import { useState, useEffect, useRef } from "react"
import { LiveIndicator } from "../components/ui/LiveIndicator"
import { SSE_URLS } from "../services/api"
import { Network, ArrowRightLeft, Filter, Trash2, Activity } from "lucide-react"

const PROTOCOL_COLORS = {
  TCP:  { badge: "bg-sky-500/15 text-sky-300 border-sky-500/25",          card: "border-sky-500/40",    label: "text-sky-400"    },
  UDP:  { badge: "bg-violet-500/15 text-violet-300 border-violet-500/25", card: "border-violet-500/40", label: "text-violet-400" },
  ICMP: { badge: "bg-amber-500/15 text-amber-300 border-amber-500/25",    card: "border-amber-500/40",  label: "text-amber-400"  },
  ARP:  { badge: "bg-rose-500/15 text-rose-300 border-rose-500/25",       card: "border-rose-500/40",   label: "text-rose-400"   },
}

// Typos connues dans la DB
const PROTOCOL_ALIASES = {
  IMCP: "ICMP", ICMP: "ICMP", TCP: "TCP", UDP: "UDP", ARP: "ARP",
}

const MAX_PACKETS = 200
// Colonnes dynamiques selon les champs présents
const COL_FULL    = "155px 68px 1fr 1fr 70px 70px"  // avec ports
const COL_NO_PORT = "155px 68px 1fr 1fr 70px"        // sans ports

// ── Timestamp : gère ISODate MongoDB sérialisé de plusieurs façons ──────────
// MongoDB via JSON.stringify sérialise ISODate en :
//   - string ISO  : "2026-05-30T10:05:55.274Z"  ✓ new Date() le gère
//   - objet       : { "$date": "2026-05-30T..." } ou { "$date": { "$numberLong": "..." } }
//   - nombre ms   : 1748599555274
function parseTimestamp(ts) {
  if (ts == null) return null

  // Objet MongoDB extended JSON : { "$date": "..." } ou { "$date": { "$numberLong": "1234" } }
  if (typeof ts === "object" && ts !== null && !Array.isArray(ts)) {
    const inner = ts["$date"]
    if (inner != null) return parseTimestamp(inner)
    // ISODate déjà converti en objet Date par certains drivers
    if (ts instanceof Date) return isNaN(ts.getTime()) ? null : ts
    return null
  }

  // Nombre : Unix ms (> 1e10) ou secondes (< 1e10)
  if (typeof ts === "number") {
    const d = new Date(ts < 1e10 ? ts * 1000 : ts)
    return isNaN(d.getTime()) ? null : d
  }

  if (typeof ts === "string") {
    const s = ts.trim()
    // Heure seule "HH:MM:SS"
    if (/^\d{2}:\d{2}:\d{2}/.test(s) && s.length <= 12) return s
    // String numérique (depuis $numberLong)
    if (/^\d+$/.test(s)) {
      const n = Number(s)
      return parseTimestamp(n)
    }
    // ISO ou "YYYY-MM-DD HH:MM:SS"
    const d = new Date(s.replace(" ", "T"))
    return isNaN(d.getTime()) ? null : d
  }

  return null
}

function formatTime(ts) {
  const p = parseTimestamp(ts)
  if (!p) return "—"
  if (typeof p === "string") return p
  return p.toLocaleString("fr-FR", {
    day:    "2-digit",
    month:  "2-digit",
    year:   "numeric",
    hour:   "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  })
}

function normalizePacket(raw) {
  const proto = raw.protocol ? String(raw.protocol).toUpperCase().trim() : "?"
  return {
    ...raw,
    protocol: PROTOCOL_ALIASES[proto] ?? proto,
  }
}

function matchesFilter(p, q) {
  if (!q) return true
  const lq = q.toLowerCase().trim()
  return [
    p.ip_src,
    p.ip_dst,
    p.port_src != null ? String(p.port_src) : null,
    p.port_dst != null ? String(p.port_dst) : null,
    p.protocol,
    p.iface,
  ].some(v => v && v.toLowerCase().includes(lq))
}

// Détermine si AU MOINS un paquet du lot a des ports
function hasPorts(packets) {
  return packets.some(p => p.port_src != null || p.port_dst != null)
}

export function Dashboard() {
  const [packets, setPackets]         = useState([])
  const [connected, setConnected]     = useState(false)
  const [paused, setPaused]           = useState(false)
  const [filter, setFilter]           = useState("")
  const [protoFilter, setProtoFilter] = useState("ALL")
  const pausedRef      = useRef(false)
  const eventSourceRef = useRef(null)

  useEffect(() => {
    const connect = () => {
      const es = new EventSource(SSE_URLS.packets)
      eventSourceRef.current = es
      es.onopen    = () => setConnected(true)
      es.onmessage = (e) => {
        if (pausedRef.current) return
        try {
          const pkt = normalizePacket(JSON.parse(e.data))
          setPackets(prev => [pkt, ...prev].slice(0, MAX_PACKETS))
        } catch (_) {}
      }
      es.onerror = () => {
        setConnected(false)
        es.close()
        setTimeout(connect, 3000)
      }
    }
    connect()
    return () => eventSourceRef.current?.close()
  }, [])

  useEffect(() => { pausedRef.current = paused }, [paused])

  const filtered = packets.filter(p =>
    (protoFilter === "ALL" || p.protocol === protoFilter) && matchesFilter(p, filter)
  )

  const stats = packets.reduce((acc, p) => {
    acc[p.protocol] = (acc[p.protocol] || 0) + 1
    return acc
  }, {})

  const showPorts = hasPorts(filtered)
  const colTemplate = showPorts ? COL_FULL : COL_NO_PORT

  return (
    <div className="w-full space-y-3 pr-4">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Network className="text-sky-400 w-4 h-4" />
          <div>
            <h1 className="text-sm font-mono font-semibold text-white">Surveillance réseau</h1>
          </div>
          <LiveIndicator connected={connected} />
        </div>
        <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-500 bg-slate-800/60 border border-slate-700/50 rounded px-2 py-1">
          <Activity className="w-3 h-3" />
          <span>{packets.length} paquets</span>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-2">
        {["TCP", "UDP", "ICMP", "ARP"].map(proto => {
          const c      = PROTOCOL_COLORS[proto]
          const active = protoFilter === proto
          return (
            <button
              key={proto}
              onClick={() => setProtoFilter(p => p === proto ? "ALL" : proto)}
              className={[
                "relative bg-slate-900 border rounded-lg p-3 text-left transition-all duration-150",
                active ? `${c.card} ring-1 ring-inset ${c.card}` : "border-slate-700/50 hover:border-slate-600/80",
              ].join(" ")}
            >
              <p className={`text-[10px] font-mono font-bold tracking-widest ${c.label}`}>{proto}</p>
              <p className="text-2xl font-mono font-bold text-white tabular-nums leading-none mt-1">
                {stats[proto] || 0}
              </p>
              {active && (
                <span className={`absolute top-1.5 right-1.5 text-[8px] font-mono font-bold px-1 py-px rounded border ${c.badge}`}>
                  ON
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-2">
        <div className="flex-1 relative">
          <Filter className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-slate-500 pointer-events-none" />
          <input
            type="text"
            placeholder="IP, port, protocole, interface…"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700/50 rounded-lg pl-8 pr-8 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-sky-500/40 focus:ring-1 focus:ring-sky-500/10 transition-all"
          />
          {filter && (
            <button
              onClick={() => setFilter("")}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-white text-base leading-none"
            >×</button>
          )}
        </div>
        <button
          onClick={() => setPaused(p => !p)}
          className={[
            "px-3 py-1.5 rounded-lg text-[11px] font-mono font-bold border transition-all whitespace-nowrap",
            paused
              ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
              : "bg-amber-500/10 text-amber-400 border-amber-500/30",
          ].join(" ")}
        >
          {paused ? "▶ REPRENDRE" : "⏸ PAUSE"}
        </button>
        <button
          onClick={() => setPackets([])}
          className="p-1.5 rounded-lg text-slate-500 border border-slate-700/50 hover:text-red-400 hover:border-red-500/30 transition-all"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="w-full border border-slate-700/50 rounded-lg overflow-hidden bg-slate-900/80">

        {(filter || protoFilter !== "ALL") && (
          <div className="px-3 py-1 bg-sky-950/60 border-b border-sky-900/40 flex items-center gap-2 text-[10px] font-mono text-sky-400">
            <span>{filtered.length} résultat{filtered.length !== 1 ? "s" : ""}</span>
            {protoFilter !== "ALL" && <span className="text-slate-500">· {protoFilter}</span>}
            {filter && <span className="text-slate-500">· "{filter}"</span>}
            <button
              onClick={() => { setFilter(""); setProtoFilter("ALL") }}
              className="ml-auto text-slate-600 hover:text-slate-300"
            >réinitialiser ×</button>
          </div>
        )}
        <div
          className="grid border-b border-slate-700/50 bg-slate-800/70 text-[9px] font-mono text-slate-500 uppercase tracking-widest"
          style={{ gridTemplateColumns: colTemplate }}
        >
          <div className="px-3 py-2">Timestamp</div>
          <div className="px-2 py-2">Proto</div>
          <div className="px-3 py-2">IP Source</div>
          <div className="px-3 py-2">IP Destination</div>
          {showPorts && <div className="px-2 py-2 text-right">Port</div>}
          <div className="px-2 py-2">Iface</div>
        </div>

        <div className="overflow-y-auto" style={{ maxHeight: "calc(100vh - 320px)" }}>
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-slate-700">
              <ArrowRightLeft className="w-6 h-6 mb-2 opacity-30" />
              <p className="font-mono text-xs">
                {connected ? "En attente de paquets…" : "Connexion au sniffer…"}
              </p>
            </div>
          ) : (
            filtered.map((pkt, i) => (
              <PacketRow
                key={pkt._id ?? i}
                packet={pkt}
                index={i}
                showPorts={showPorts}
                colTemplate={colTemplate}
              />
            ))
          )}
        </div>
      </div>

      <div className="flex items-center justify-between text-[10px] font-mono text-slate-700 pb-1">
        <span><span className="text-slate-400">{filtered.length}</span> / {packets.length} paquets</span>
        <span>buffer {MAX_PACKETS}</span>
      </div>

    </div>
  )
}

function PacketRow({ packet, index, showPorts, colTemplate }) {
  const c        = PROTOCOL_COLORS[packet.protocol]
  const badgeCls = c?.badge ?? "bg-slate-700/40 text-slate-400 border-slate-600/30"
  const rowBg    = index % 2 !== 0 ? "bg-slate-800/25" : ""
  const isNew    = index === 0

  return (
    <div
      className={[
        "grid border-b border-slate-800/60 text-[11px] font-mono",
        "hover:bg-slate-700/20 cursor-default transition-colors",
        rowBg,
        isNew ? "animate-pulse-live" : "",
      ].join(" ")}
      style={{ gridTemplateColumns: colTemplate }}
    >
      <div className="px-3 py-1.5 text-slate-400 tabular-nums whitespace-nowrap">
        {formatTime(packet.timestamp)}
      </div>

      <div className="px-2 py-1.5 flex items-center">
        <span className={`px-1.5 py-px rounded text-[9px] border font-bold ${badgeCls}`}>
          {packet.protocol}
        </span>
      </div>

      <div className="px-3 py-1.5 text-sky-400 truncate">
        {packet.ip_src || "—"}
        {showPorts && packet.port_src != null && (
          <span className="text-slate-600">:{packet.port_src}</span>
        )}
      </div>

      <div className="px-3 py-1.5 text-slate-300 truncate">
        {packet.ip_dst || "—"}
        {showPorts && packet.port_dst != null && (
          <span className="text-slate-600">:{packet.port_dst}</span>
        )}
      </div>

      {showPorts && (
        <div className="px-2 py-1.5 text-slate-500 tabular-nums text-right">
          {packet.port_dst ?? "—"}
        </div>
      )}

      <div className="px-2 py-1.5 text-slate-600 truncate">
        {packet.iface || "—"}
      </div>
    </div>
  )
}