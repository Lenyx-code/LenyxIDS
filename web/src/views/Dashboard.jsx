import { useState, useMemo, memo } from "react"
import { Network, ArrowRightLeft, Filter, Trash2, Activity, Pause, Play } from "lucide-react"
import { LiveIndicator }  from "../components/ui/LiveIndicator"
import { useSSEStore}    from "../store/sseStore"
import { formatTime }     from "../utils/formatters"

const PROTOCOL_COLORS = {
  TCP:  { badge: "bg-blue-500/10 text-blue-400 border-blue-500/20",     label: "text-blue-400"   },
  UDP:  { badge: "bg-purple-500/10 text-purple-400 border-purple-500/20", label: "text-purple-400" },
  ICMP: { badge: "bg-amber-500/10 text-amber-400 border-amber-500/20",   label: "text-amber-400"  },
  ARP:  { badge: "bg-rose-500/10 text-rose-400 border-rose-500/20",      label: "text-rose-400"   },
}

const COL_FULL    = "160px 64px 1fr 1fr 64px 72px"
const COL_NO_PORT = "160px 64px 1fr 1fr 72px"

function matchesFilter(p, q) {
  if (!q) return true
  const lq = q.toLowerCase()
  return [
    p.ip_src, p.ip_dst, p.protocol, p.iface,
    p.port_src != null ? String(p.port_src) : null,
    p.port_dst != null ? String(p.port_dst) : null,
  ].some(v => v?.toLowerCase().includes(lq))
}

function hasPorts(packets) {
  return packets.some(p => p.port_src != null || p.port_dst != null)
}

export function Dashboard() {
  // Store global SSE
  const packets      = useSSEStore((state) => state.packets)
  const pktConn      = useSSEStore((state) => state.pktConn)
  const setPaused    = useSSEStore((state) => state.setPaused)
  const clearPackets = useSSEStore((state) => state.clearPackets)

  // State local
  const [paused,      setPausedLocal] = useState(false)
  const [filter,      setFilter]      = useState("")
  const [protoFilter, setProtoFilter] = useState("ALL")

  const handlePause = () => {
    const next = !paused
    setPausedLocal(next)
    setPaused(next)
  }

  // Recalculs coûteux mémoïsés : ne se refont que si packets/filtre changent réellement
  const filtered = useMemo(
    () => packets.filter(p =>
      (protoFilter === "ALL" || p.protocol === protoFilter) &&
      matchesFilter(p, filter)
    ),
    [packets, protoFilter, filter]
  )

  const stats = useMemo(
    () => packets.reduce((acc, p) => {
      acc[p.protocol] = (acc[p.protocol] || 0) + 1
      return acc
    }, {}),
    [packets]
  )

  const showPorts   = useMemo(() => hasPorts(filtered), [filtered])
  const colTemplate = showPorts ? COL_FULL : COL_NO_PORT

  return (
    <div className="w-full space-y-3 pr-4">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Network className="text-slate-500 w-4 h-4" />
          <h1 className="text-sm font-mono font-semibold text-white">Surveillance réseau</h1>
          <LiveIndicator connected={pktConn} />
        </div>
        <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-500 bg-slate-800 border border-slate-700 rounded px-2 py-1">
          <Activity className="w-3 h-3" />
          <span>{packets.length} paquets</span>
        </div>
      </div>

      {/* Stat cards protocoles */}
      <div className="grid grid-cols-4 gap-2">
        {["TCP", "UDP", "ICMP", "ARP"].map(proto => {
          const colors = PROTOCOL_COLORS[proto]
          const active = protoFilter === proto
          return (
            <button
              key={proto}
              onClick={() => setProtoFilter(p => p === proto ? "ALL" : proto)}
              className={`relative bg-cyber-card border rounded-lg p-3 text-left transition-all ${
                active ? "border-cyber-accent ring-1 ring-cyber-accent/30" : "border-cyber-border hover:border-cyber-border/80"
              }`}
            >
              <p className={`text-[10px] font-mono font-bold tracking-widest ${colors.label}`}>{proto}</p>
              <p className="text-2xl font-mono font-bold text-white tabular-nums leading-none mt-1">
                {stats[proto] || 0}
              </p>
              {active && (
                <span className={`absolute top-1.5 right-1.5 text-[8px] font-mono font-bold px-1 py-px rounded border ${colors.badge}`}>
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
            className="w-full bg-cyber-card border border-cyber-border rounded-lg pl-8 pr-8 py-1.5 text-xs font-mono text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyber-accent/50 transition-all"
          />
          {filter && (
            <button
              onClick={() => setFilter("")}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-white text-base leading-none"
            >×</button>
          )}
        </div>

        <button
          onClick={handlePause}
          className="p-1.5 rounded-lg text-slate-500 border border-cyber-border hover:text-cyber-accent hover:border-cyber-accent/30 transition-all"
          title={paused ? "Reprendre le flux" : "Mettre en pause"}
        >
          {paused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
        </button>

        <button
          onClick={clearPackets}
          className="p-1.5 rounded-lg text-slate-500 border border-cyber-border hover:text-red-400 hover:border-red-500/30 transition-all"
          title="Vider le buffer"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Tableau */}
      <div className="w-full border border-cyber-border rounded-lg overflow-hidden bg-cyber-card">

        {(filter || protoFilter !== "ALL") && (
          <div className="px-3 py-1 bg-cyber-surface border-b border-cyber-border flex items-center gap-2 text-[10px] font-mono text-slate-500">
            <span>{filtered.length} résultat{filtered.length !== 1 ? "s" : ""}</span>
            {protoFilter !== "ALL" && <span className="text-slate-600">· {protoFilter}</span>}
            {filter && <span className="text-slate-600">· "{filter}"</span>}
            <button
              onClick={() => { setFilter(""); setProtoFilter("ALL") }}
              className="ml-auto text-slate-600 hover:text-slate-300"
            >réinitialiser ×</button>
          </div>
        )}

        {/* Header colonnes */}
        <div
          className="grid border-b border-cyber-border bg-cyber-surface text-[9px] font-mono text-slate-500 uppercase tracking-widest"
          style={{ gridTemplateColumns: colTemplate }}
        >
          <div className="px-3 py-2">Timestamp</div>
          <div className="px-2 py-2">Proto</div>
          <div className="px-3 py-2">IP source</div>
          <div className="px-3 py-2">IP destination</div>
          {showPorts && <div className="px-2 py-2 text-right">Port</div>}
          <div className="px-2 py-2">Iface</div>
        </div>

        <div className="overflow-y-auto" style={{ maxHeight: "calc(100vh - 330px)" }}>
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-slate-600">
              <ArrowRightLeft className="w-6 h-6 mb-2 opacity-30" />
              <p className="font-mono text-xs">
                {pktConn ? "En attente de paquets…" : "Connexion au sniffer…"}
              </p>
            </div>
          ) : (
            filtered.map((pkt, i) => (
              <PacketRow
                key={pkt._cid ?? pkt._id ?? i}
                packet={pkt}
                index={i}
                showPorts={showPorts}
                colTemplate={colTemplate}
              />
            ))
          )}
        </div>
      </div>

      <div className="flex items-center justify-between text-[10px] font-mono text-slate-600 pb-1">
        <span><span className="text-slate-400">{filtered.length}</span> / {packets.length} paquets</span>
        <span>buffer 200</span>
      </div>
    </div>
  )
}

// Mémoïsé : évite de re-rendre les 200 lignes quand seule une partie change.
// Utile même avec le batching, car les paquets en fin de liste ne changent pas
// de contenu d'un flush à l'autre (seule leur position peut varier).
const PacketRow = memo(function PacketRow({ packet, index, showPorts, colTemplate }) {
  const colors   = PROTOCOL_COLORS[packet.protocol]
  const badgeCls = colors?.badge ?? "bg-slate-700 text-slate-400 border-slate-600"
  const rowBg    = index % 2 !== 0 ? "bg-cyber-surface/30" : ""

  return (
    <div
      className={`grid border-b border-cyber-border/30 text-[11px] font-mono hover:bg-cyber-accent/5 transition-colors cursor-default ${rowBg} ${index === 0 ? "animate-pulse-live" : ""}`}
      style={{ gridTemplateColumns: colTemplate }}
    >
      <div className="px-3 py-1.5 text-slate-500 tabular-nums whitespace-nowrap">
        {formatTime(packet.timestamp)}
      </div>
      <div className="px-2 py-1.5 flex items-center">
        <span className={`px-1.5 py-px rounded text-[9px] border font-bold ${badgeCls}`}>
          {packet.protocol}
        </span>
      </div>
      <div className="px-3 py-1.5 text-cyber-accent truncate">
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
})