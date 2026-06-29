import { useState, useEffect, useCallback } from "react"
import { API } from "../services/api"
import {
  FileText, RefreshCw, ChevronLeft, ChevronRight,ChevronDown,
  Plus, X, AlertTriangle, Eye, Shield
} from "lucide-react"
import { Badge } from "../components/ui/Badge"

// ─── Modal génération de rapport ───────────────────────────────
function GenerateReportModal({ onClose, onGenerated }) {
  const [attackers,   setAttackers]   = useState([])
  const [attackerIp,  setAttackerIp]  = useState("")
  const [victimIp,     setVictimIp]    = useState("")
  const [loading,      setLoading]     = useState(false)
  const [error,        setError]       = useState(null)

  useEffect(() => {
    API.getDistinctAttackers()
      .then(res => setAttackers(res.data.data || []))
      .catch(() => {})
  }, [])

  const handleGenerate = async () => {
    if (!attackerIp || !victimIp) {
      setError("Renseigne l'IP attaquante et l'IP victime")
      return
    }
    setLoading(true)
    setError(null)
    try {
      const res = await API.generateReport(attackerIp, victimIp)
      if (res.data.error) {
        setError(res.data.error)
      } else {
        onGenerated()
        onClose()
      }
    } catch (e) {
      setError("Erreur lors de la génération")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl w-full max-w-md mx-4 shadow-xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-5 border-b border-slate-200 dark:border-slate-700">
          <h2 className="font-mono font-semibold text-slate-800 dark:text-slate-200 text-sm">
            Générer un rapport d'incident
          </h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 p-1 rounded">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          <div>
            <label className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1.5">
              IP Attaquante
            </label>
            <select
              value={attackerIp}
              onChange={e => setAttackerIp(e.target.value)}
              className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-600 dark:text-slate-300 focus:outline-none focus:border-slate-400"
            >
              <option value="">Sélectionner une IP...</option>
              {attackers.map(ip => <option key={ip} value={ip}>{ip}</option>)}
            </select>
          </div>

          <div>
            <label className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1.5">
              IP Victime
            </label>
            <input
              type="text"
              placeholder="ex: 172.20.0.3"
              value={victimIp}
              onChange={e => setVictimIp(e.target.value)}
              className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-600 dark:text-slate-300 placeholder-slate-400 focus:outline-none focus:border-slate-400"
            />
          </div>

          {error && (
            <div className="flex items-center gap-2 text-xs font-mono text-red-500 bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800 rounded-lg p-2.5">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              {error}
            </div>
          )}

          <button
            onClick={handleGenerate}
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-xs font-mono font-semibold bg-blue-500 text-white hover:bg-blue-600 disabled:opacity-50 transition-all"
          >
            {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Shield className="w-3.5 h-3.5" />}
            {loading ? "Génération en cours..." : "Générer le rapport"}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Modal détail rapport ───────────────────────────────────────
function ReportDetailModal({ report, onClose }) {
  const [showTimeline, setShowTimeline] = useState(true)
  if (!report) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl w-full max-w-2xl mx-4 shadow-xl max-h-[85vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-5 border-b border-slate-200 dark:border-slate-700 sticky top-0 bg-white dark:bg-slate-900">
          <div>
            <h2 className="font-mono font-semibold text-slate-800 dark:text-slate-200 text-sm">
              {report.incident_id}
            </h2>
            <p className="text-xs font-mono text-slate-400 mt-0.5">{report.title}</p>
          </div>
          <div className="flex items-center gap-2">
            <Badge severity={report.severity} />
            <button onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 p-1 rounded">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="p-5 space-y-4">

          {/* Infos générales */}
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: "IP Attaquante", value: report.attacker_ip, color: "text-red-500" },
              { label: "IP Victime",    value: report.victim_ip,   color: "text-slate-700 dark:text-slate-300" },
              { label: "Début",         value: new Date(report.start_date).toLocaleString("fr-FR") },
              { label: "Fin",           value: new Date(report.end_date).toLocaleString("fr-FR") },
              { label: "Total alertes", value: report.total_alerts },
              { label: "Types d'attaque", value: report.attack_types?.join(", ") },
            ].map(({ label, value, color }) => (
              <div key={label} className="bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg p-3">
                <p className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1">{label}</p>
                <p className={`text-xs font-mono font-semibold ${color || "text-slate-700 dark:text-slate-300"}`}>{value}</p>
              </div>
            ))}
          </div>

          {/* Timeline */}
          <div>
           <div className="flex items-center justify-between mb-2">
  <p className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
    Timeline de l'incident
  </p>
  <button
    onClick={() => setShowTimeline(!showTimeline)}
    className="p-1 rounded border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-blue-500 hover:border-blue-300 transition-all"
    title={showTimeline ? "Masquer les détails" : "Voir les détails"}
  >
    {/* L'icône pivote selon l'état d'ouverture */}
    <ChevronDown className={`w-3 h-3 transform transition-transform ${showTimeline ? 'rotate-180' : ''}`} />
  </button>
</div>

<div className="space-y-2">
  {/* On vérifie l'état AVANT de mapper pour de meilleures performances */}
  {showTimeline && report.timeline?.map((event, i) => (
    <div key={i} className="flex items-start gap-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg p-3">
      <div className="w-1.5 h-1.5 rounded-full bg-red-400 mt-1.5 shrink-0" />
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-semibold text-slate-700 dark:text-slate-300">
            {event.attack_type.replace(/_/g, " ")}
          </span>
          <span className="text-[10px] font-mono text-slate-400">
            {new Date(event.time).toLocaleString("fr-FR")}
          </span>
        </div>
        <p className="text-xs font-mono text-slate-500 mt-1">{event.description}</p>
      </div>
    </div>
  ))}
</div>
          </div>

          {/* Conclusion */}
          <div>
            <p className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-2">Conclusion</p>
            <p className="text-xs font-mono text-slate-600 dark:text-slate-300 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg p-3">
              {report.conclusion}
            </p>
          </div>

          {/* Recommandations */}
          <div>
            <p className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-2">Recommandations</p>
            <ul className="space-y-1.5">
              {report.recommendations?.map((rec, i) => (
                <li key={i} className="flex items-start gap-2 text-xs font-mono text-slate-600 dark:text-slate-300">
                  <span className="text-emerald-500 mt-0.5">→</span>
                  {rec}
                </li>
              ))}
            </ul>
          </div>

          {/* Preuves */}
          <div className="grid grid-cols-2 gap-3">
            {report.pcap_file && (
              <div className="bg-blue-50 dark:bg-blue-900/10 border border-blue-200 dark:border-blue-800 rounded-lg p-3">
                <p className="text-[10px] font-mono text-blue-600 dark:text-blue-400 uppercase tracking-wider mb-1">Fichier PCAP</p>
                <p className="text-[10px] font-mono text-slate-500 break-all">{report.pcap_file}</p>
              </div>
            )}
            {report.integrity_hash && (
              <div className="bg-emerald-50 dark:bg-emerald-900/10 border border-emerald-200 dark:border-emerald-800 rounded-lg p-3">
                <p className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 uppercase tracking-wider mb-1">Hash SHA-256</p>
                <p className="text-[10px] font-mono text-slate-500 break-all">{report.integrity_hash}</p>
              </div>
            )}
          </div>

        </div>
      </div>
    </div>
  )
}

// ─── Vue principale ─────────────────────────────────────────────
export function Reports() {
  const [reports,    setReports]    = useState([])
  const [loading,     setLoading]    = useState(false)
  const [showGenerate, setShowGenerate] = useState(false)
  const [selected,    setSelected]   = useState(null)

  const [page,       setPage]       = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [total,       setTotal]      = useState(0)

  const fetchReports = useCallback(async () => {
    setLoading(true)
    try {
      const res = await API.getReports()
      setReports(res.data.data || [])
      setTotal(res.data.total || 0)
      setTotalPages(res.data.total_pages || 1)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchReports() }, [fetchReports])

  return (
    <>
      {showGenerate && (
        <GenerateReportModal
          onClose={() => setShowGenerate(false)}
          onGenerated={fetchReports}
        />
      )}
      {selected && (
        <ReportDetailModal report={selected} onClose={() => setSelected(null)} />
      )}

      <div className="flex flex-col h-full overflow-hidden gap-3">

        {/* Header */}
        <div className="flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <FileText className="w-4 h-4 text-slate-500" />
            <h1 className="text-sm font-mono font-semibold text-slate-800 dark:text-slate-200">
              Rapports d'incidents
            </h1>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-400">{total} rapport{total > 1 ? "s" : ""}</span>
            <button
              onClick={() => setShowGenerate(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold bg-blue-500 text-white hover:bg-blue-600 transition-all"
            >
              <Plus className="w-3.5 h-3.5" />
              Nouveau rapport
            </button>
            <button
              onClick={fetchReports}
              className="p-2 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-blue-500 transition-all"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            </button>
          </div>
        </div>

        {/* Liste */}
        <div className="flex-1 min-h-0 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg overflow-hidden flex flex-col">
          <div className="grid grid-cols-12 gap-2 px-4 py-2.5 border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-[9px] font-mono text-slate-400 uppercase tracking-widest shrink-0">
            <div className="col-span-2">Incident ID</div>
            <div className="col-span-3">Titre</div>
            <div className="col-span-1">Sévérité</div>
            <div className="col-span-2">Attaquant</div>
            <div className="col-span-2">Généré le</div>
            <div className="col-span-1">Alertes</div>
            <div className="col-span-1">Actions</div>
          </div>

          <div className="overflow-y-auto flex-1 min-h-0">
            {loading ? (
              <div className="flex items-center justify-center py-16">
                <RefreshCw className="w-4 h-4 text-slate-400 animate-spin" />
              </div>
            ) : reports.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 text-slate-400">
                <FileText className="w-8 h-8 mb-3 opacity-20" />
                <p className="font-mono text-xs">Aucun rapport généré</p>
                <button
                  onClick={() => setShowGenerate(true)}
                  className="mt-3 text-xs font-mono text-blue-500 hover:underline"
                >
                  Générer le premier rapport
                </button>
              </div>
            ) : (
              reports.map((report, i) => (
                <div
                  key={report._id || i}
                  className={`grid grid-cols-12 gap-2 px-4 py-2.5 border-b border-slate-100 dark:border-slate-800 text-xs font-mono hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-all cursor-default ${i % 2 !== 0 ? "bg-slate-50/60 dark:bg-slate-800/20" : ""}`}
                >
                  <div className="col-span-2 text-slate-700 dark:text-slate-300 font-semibold flex items-center truncate">
                    {report.incident_id}
                  </div>
                  <div className="col-span-3 text-slate-600 dark:text-slate-400 flex items-center truncate">
                    {report.title}
                  </div>
                  <div className="col-span-1 flex items-center">
                    <Badge severity={report.severity} />
                  </div>
                  <div className="col-span-2 text-red-500 flex items-center truncate">
                    {report.attacker_ip}
                  </div>
                  <div className="col-span-2 text-slate-400 flex items-center tabular-nums">
                    {new Date(report.generated_at).toLocaleString("fr-FR")}
                  </div>
                  <div className="col-span-1 text-slate-400 flex items-center">
                    {report.total_alerts}
                  </div>
                  <div className="col-span-1 flex items-center">
                    <button
                      onClick={() => setSelected(report)}
                      className="p-1 rounded border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-blue-500 hover:border-blue-300 transition-all"
                      title="Voir le détail"
                    >
                      <Eye className="w-3 h-3" />
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between text-xs font-mono shrink-0">
            <span className="text-slate-400">
              Page <span className="text-slate-700 dark:text-slate-300">{page}</span> / {totalPages}
            </span>
            <div className="flex items-center gap-1.5">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-400 disabled:opacity-30 transition-all">
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-400 disabled:opacity-30 transition-all">
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>
    </>
  )
}