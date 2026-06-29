import { useState, useEffect, useRef, useCallback } from "react"
import { Radar, Upload, Shield, ShieldAlert, ShieldCheck, Clock, Hash, FileText, ChevronDown, ChevronRight, RefreshCw, AlertTriangle, Cpu, X } from "lucide-react"
import { API } from "../services/api"

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEVERITY_CFG = {
  critical: { label: "Critique",  bg: "bg-red-500/10",    border: "border-red-500/30",    text: "text-red-400",    dot: "bg-red-500"    },
  high:     { label: "Élevé",     bg: "bg-orange-500/10", border: "border-orange-500/30", text: "text-orange-400", dot: "bg-orange-500" },
  medium:   { label: "Moyen",     bg: "bg-yellow-500/10", border: "border-yellow-500/30", text: "text-yellow-400", dot: "bg-yellow-500" },
  low:      { label: "Faible",    bg: "bg-blue-500/10",   border: "border-blue-500/30",   text: "text-blue-400",   dot: "bg-blue-500"   },
  none:     { label: "Sain",      bg: "bg-emerald-500/10",border: "border-emerald-500/30",text: "text-emerald-400",dot: "bg-emerald-500" },
}

const sev = (s) => SEVERITY_CFG[s] ?? SEVERITY_CFG.none

const fmt = (iso) => {
  if (!iso) return "—"
  const d = new Date(iso)
  return d.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit", year: "2-digit" }) +
    " " + d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })
}

const fmtSize = (kb) => kb >= 1024 ? `${(kb / 1024).toFixed(1)} MB` : `${kb} KB`

// ── Composant principal ───────────────────────────────────────────────────────

export function Analyse() {
  const [file,        setFile]        = useState(null)
  const [dragging,    setDragging]    = useState(false)
  const [scanning,    setScanning]    = useState(false)
  const [result,      setResult]      = useState(null)
  const [error,       setError]       = useState(null)
  const [history,     setHistory]     = useState([])
  const [histLoading, setHistLoading] = useState(true)
  const [expanded,    setExpanded]    = useState({})   // rule index → bool
  const [rulesInfo,   setRulesInfo]   = useState(null)
  const [scanProgress, setScanProgress] = useState(0)
  const dropRef  = useRef(null)
  const inputRef = useRef(null)
  const timerRef = useRef(null)

  // Charger l'historique et les infos règles
  useEffect(() => {
    loadHistory()
    API.yaraRulesInfo().then(r => setRulesInfo(r.data)).catch(() => {})
  }, [])

  const loadHistory = async () => {
    setHistLoading(true)
    try {
      const r = await API.yaraHistory({ limit: 20 })
      setHistory(r.data.data ?? [])
    } catch {
      setHistory([])
    } finally {
      setHistLoading(false)
    }
  }

  // Animation de progression pendant le scan
  const startProgressAnim = () => {
    setScanProgress(0)
    let p = 0
    timerRef.current = setInterval(() => {
      p += Math.random() * 8
      if (p >= 90) { clearInterval(timerRef.current); p = 90 }
      setScanProgress(Math.min(p, 90))
    }, 180)
  }
  const endProgressAnim = () => {
    clearInterval(timerRef.current)
    setScanProgress(100)
    setTimeout(() => setScanProgress(0), 600)
  }

  // Drag & drop
  const onDragOver  = (e) => { e.preventDefault(); setDragging(true)  }
  const onDragLeave = ()  => setDragging(false)
  const onDrop      = (e) => {
    e.preventDefault(); setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) pickFile(f)
  }
  const onInputChange = (e) => { if (e.target.files[0]) pickFile(e.target.files[0]) }

  const pickFile = (f) => {
    setFile(f)
    setResult(null)
    setError(null)
    setExpanded({})
  }

  const scan = async () => {
    if (!file || scanning) return
    setScanning(true)
    setResult(null)
    setError(null)
    setExpanded({})
    startProgressAnim()
    try {
      const r = await API.yaraScan(file)
      setResult(r.data)
      await loadHistory()
    } catch (e) {
      setError(e?.response?.data?.detail ?? "Erreur lors de l'analyse")
    } finally {
      endProgressAnim()
      setScanning(false)
    }
  }

  const reset = () => {
    setFile(null); setResult(null); setError(null)
    setExpanded({}); setScanProgress(0)
    if (inputRef.current) inputRef.current.value = ""
  }

  const toggleExpand = (i) => setExpanded(p => ({ ...p, [i]: !p[i] }))

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col h-full overflow-hidden gap-4 p-1">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Radar className="w-4 h-4 text-slate-500 dark:text-slate-400" />
          <h1 className="text-sm font-mono font-semibold text-slate-800 dark:text-slate-200">
            Analyses YARA
          </h1>
        </div>
        {rulesInfo && (
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border
            ${rulesInfo.compiled_exists
              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
              : "bg-red-500/10 border-red-500/30 text-red-400"}`}>
            {rulesInfo.compiled_exists
              ? `${rulesInfo.rule_files_count} règles chargées`
              : "Règles non disponibles"}
          </span>
        )}
      </div>

      {/* Layout principal */}
      <div className="flex flex-1 gap-4 overflow-hidden min-h-0">

        {/* Colonne gauche — upload + résultat */}
        <div className="flex flex-col gap-4 w-[55%] overflow-y-auto pr-1">

          {/* Zone de drop */}
          <div
            ref={dropRef}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
            onDrop={onDrop}
            onClick={() => !file && inputRef.current?.click()}
            className={`relative flex flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed
              transition-all duration-200 cursor-pointer select-none
              ${dragging
                ? "border-indigo-400 bg-indigo-500/10"
                : file
                  ? "border-slate-600/40 bg-slate-800/30 cursor-default"
                  : "border-slate-600/30 hover:border-slate-500/50 bg-slate-800/20 hover:bg-slate-800/30"}
              ${file ? "py-4 px-5" : "py-10 px-5"}`}
          >
            <input ref={inputRef} type="file" className="hidden" onChange={onInputChange} />

            {!file ? (
              <>
                <div className="p-3 rounded-full bg-slate-700/50">
                  <Upload className="w-5 h-5 text-slate-400" />
                </div>
                <div className="text-center">
                  <p className="text-xs font-medium text-slate-300">Déposez un fichier ici</p>
                  <p className="text-[11px] text-slate-500 mt-0.5">ou cliquez pour parcourir — max 50 MB</p>
                </div>
              </>
            ) : (
              <div className="flex items-center justify-between w-full gap-3">
                <div className="flex items-center gap-2 min-w-0">
                  <div className="p-1.5 rounded-lg bg-indigo-500/15 shrink-0">
                    <FileText className="w-4 h-4 text-indigo-400" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs font-mono font-medium text-slate-200 truncate">{file.name}</p>
                    <p className="text-[10px] text-slate-500">{fmtSize(file.size / 1024)}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={(e) => { e.stopPropagation(); inputRef.current?.click() }}
                    className="text-[10px] text-slate-400 hover:text-slate-200 transition-colors px-2 py-1 rounded-lg hover:bg-slate-700/50"
                  >
                    Changer
                  </button>
                  <button
                    onClick={(e) => { e.stopPropagation(); reset() }}
                    className="p-1 rounded-lg hover:bg-slate-700/50 text-slate-500 hover:text-slate-300 transition-colors"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Bouton scanner */}
          {file && (
            <button
              onClick={scan}
              disabled={scanning}
              className={`flex items-center justify-center gap-2 w-full py-2.5 rounded-xl text-xs font-semibold
                transition-all duration-200
                ${scanning
                  ? "bg-indigo-600/50 text-indigo-300 cursor-not-allowed"
                  : "bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-500/20"}`}
            >
              {scanning ? (
                <>
                  <Cpu className="w-3.5 h-3.5 animate-pulse" />
                  Analyse en cours...
                </>
              ) : (
                <>
                  <Shield className="w-3.5 h-3.5" />
                  Lancer l'analyse YARA
                </>
              )}
            </button>
          )}

          {/* Barre de progression */}
          {scanning && (
            <div className="flex flex-col gap-1.5">
              <div className="h-1 w-full bg-slate-700/50 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-indigo-500 to-violet-500 rounded-full transition-all duration-300"
                  style={{ width: `${scanProgress}%` }}
                />
              </div>
              <div className="flex items-center gap-1.5">
                {[
                  "Calcul SHA256",
                  "Chargement règles",
                  "Correspondances",
                  "Évaluation",
                ].map((step, i) => {
                  const threshold = (i + 1) * 22
                  const active = scanProgress >= threshold - 22 && scanProgress < threshold
                  const done   = scanProgress >= threshold
                  return (
                    <div key={i} className="flex items-center gap-1">
                      <div className={`w-1.5 h-1.5 rounded-full transition-all duration-300
                        ${done ? "bg-emerald-400" : active ? "bg-indigo-400 animate-pulse" : "bg-slate-600"}`}
                      />
                      <span className={`text-[10px] font-mono transition-colors duration-300
                        ${done ? "text-emerald-400" : active ? "text-indigo-300" : "text-slate-600"}`}>
                        {step}
                      </span>
                      {i < 3 && <span className="text-slate-700 text-[10px]">›</span>}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Erreur */}
          {error && (
            <div className="flex items-start gap-2.5 p-3 rounded-xl bg-red-500/10 border border-red-500/20">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <p className="text-xs text-red-300">{error}</p>
            </div>
          )}

          {/* Résultat */}
          {result && <ScanResult result={result} expanded={expanded} toggle={toggleExpand} />}
        </div>

        {/* Colonne droite — historique */}
        <div className="flex flex-col gap-3 flex-1 overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono font-medium text-slate-400 uppercase tracking-wider">
              Historique
            </span>
            <button
              onClick={loadHistory}
              className="p-1 rounded-lg hover:bg-slate-700/50 text-slate-500 hover:text-slate-300 transition-colors"
            >
              <RefreshCw className="w-3 h-3" />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto flex flex-col gap-2 pr-1">
            {histLoading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="h-14 rounded-xl bg-slate-800/40 animate-pulse" />
              ))
            ) : history.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-32 gap-2 text-slate-600">
                <FileText className="w-5 h-5" />
                <span className="text-xs">Aucune analyse effectuée</span>
              </div>
            ) : (
              history.map((scan) => (
                <HistoryRow key={scan._id} scan={scan} />
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Résultat du scan ──────────────────────────────────────────────────────────

function ScanResult({ result, expanded, toggle }) {
  const cfg = sev(result.severity)
  const isClean = result.status === "clean"

  return (
    <div className={`flex flex-col gap-3 p-4 rounded-xl border ${cfg.bg} ${cfg.border}`}>

      {/* En-tête résultat */}
      <div className="flex items-center gap-3">
        {isClean
          ? <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
          : <ShieldAlert className={`w-5 h-5 shrink-0 ${cfg.text}`} />
        }
        <div className="flex-1 min-w-0">
          <p className={`text-sm font-semibold ${cfg.text}`}>
            {isClean ? "Fichier sain" : `Menace détectée — ${cfg.label}`}
          </p>
          <p className="text-[11px] text-slate-400 font-mono truncate">{result.file_name}</p>
        </div>
        <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${cfg.bg} ${cfg.border} ${cfg.text}`}>
          {result.rules_source === "builtin" ? "règles embarquées" : "règles communautaires"}
        </span>
      </div>

      {/* Méta */}
      <div className="grid grid-cols-2 gap-2">
        {[
          { icon: Hash,      label: "SHA256",  val: result.sha256?.slice(0, 16) + "…" },
          { icon: FileText,  label: "Taille",  val: fmtSize(result.file_size_kb) },
          { icon: Shield,    label: "Règles",  val: `${result.rules_matched} correspondance${result.rules_matched !== 1 ? "s" : ""}` },
          { icon: Clock,     label: "Scanné",  val: fmt(result.scanned_at) },
        ].map(({ icon: Icon, label, val }) => (
          <div key={label} className="flex items-center gap-2 p-2 rounded-lg bg-slate-800/40">
            <Icon className="w-3 h-3 text-slate-500 shrink-0" />
            <div className="min-w-0">
              <p className="text-[9px] text-slate-500 uppercase tracking-wider">{label}</p>
              <p className="text-[11px] font-mono text-slate-200 truncate">{val}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Catégories */}
      {result.categories?.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {result.categories.map((cat) => (
            <span key={cat} className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-slate-700/60 text-slate-300 border border-slate-600/30">
              {cat}
            </span>
          ))}
        </div>
      )}

      {/* Règles matchées */}
      {result.matches?.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <p className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Règles déclenchées</p>
          {result.matches.map((match, i) => (
            <div key={i} className="rounded-lg border border-slate-700/40 overflow-hidden">
              <button
                onClick={() => toggle(i)}
                className="flex items-center justify-between w-full px-3 py-2 hover:bg-slate-700/30 transition-colors"
              >
                <div className="flex items-center gap-2">
                  {expanded[i]
                    ? <ChevronDown className="w-3 h-3 text-slate-500" />
                    : <ChevronRight className="w-3 h-3 text-slate-500" />
                  }
                  <span className="text-[11px] font-mono font-medium text-slate-200">{match.rule}</span>
                </div>
                <div className="flex items-center gap-1.5">
                  {match.tags?.slice(0, 2).map((t) => (
                    <span key={t} className="text-[9px] px-1.5 py-0.5 rounded bg-slate-700/80 text-slate-400 font-mono">
                      {t}
                    </span>
                  ))}
                </div>
              </button>

              {expanded[i] && (
                <div className="px-3 pb-3 pt-1 bg-slate-900/30 flex flex-col gap-2 border-t border-slate-700/30">
                  {match.meta?.description && (
                    <p className="text-[11px] text-slate-400">{match.meta.description}</p>
                  )}
                  {match.strings?.length > 0 && (
                    <div className="flex flex-col gap-1">
                      <p className="text-[9px] font-mono text-slate-600 uppercase tracking-wider">Chaînes détectées</p>
                      {match.strings.map((s, si) => (
                        <div key={si} className="flex items-start gap-2 font-mono">
                          <span className="text-[10px] text-indigo-400 shrink-0">{s.identifier}</span>
                          <span className="text-[10px] text-slate-400 break-all">{s.data}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Ligne d'historique ────────────────────────────────────────────────────────

function HistoryRow({ scan }) {
  const cfg      = sev(scan.severity)
  const isClean  = scan.status === "clean"
  const isError  = scan.status === "error"

  return (
    <div className={`flex items-center gap-3 p-3 rounded-xl border transition-colors
      ${isError
        ? "bg-slate-800/30 border-slate-700/30"
        : `${cfg.bg} ${cfg.border}`}`}
    >
      <div className={`p-1.5 rounded-lg shrink-0 ${isClean ? "bg-emerald-500/15" : isError ? "bg-slate-700/50" : "bg-red-500/15"}`}>
        {isClean
          ? <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          : isError
            ? <AlertTriangle className="w-3.5 h-3.5 text-slate-500" />
            : <ShieldAlert className={`w-3.5 h-3.5 ${cfg.text}`} />
        }
      </div>

      <div className="flex-1 min-w-0">
        <p className="text-[11px] font-mono font-medium text-slate-200 truncate">
          {scan.file_name ?? "fichier inconnu"}
        </p>
        <div className="flex items-center gap-2 mt-0.5">
          <span className="text-[10px] text-slate-500">{fmt(scan.scanned_at)}</span>
          {!isClean && !isError && (
            <span className={`text-[10px] ${cfg.text}`}>
              {scan.rules_matched} règle{scan.rules_matched !== 1 ? "s" : ""}
            </span>
          )}
        </div>
      </div>

      <div className="flex items-center gap-1.5 shrink-0">
        <div className={`w-1.5 h-1.5 rounded-full ${isError ? "bg-slate-600" : cfg.dot}`} />
        <span className={`text-[10px] font-mono ${isError ? "text-slate-500" : cfg.text}`}>
          {isError ? "erreur" : isClean ? "sain" : cfg.label}
        </span>
      </div>
    </div>
  )
}