// AlertMonitorToast.jsx — Toasts alertes MONITORING (SYSTEM_ANOMALY)
// Importé dans Layout.jsx ou l'arborescence globale de votre application

import { useEffect, useRef, useState } from "react"
import { ShieldAlert, Cpu, HardDrive, MemoryStick, Terminal, Network, FileText, X } from "lucide-react"

// Un composant Badge local simple si vous n'utilisez pas de librairie externe
function Badge({ severity }) {
  const styles = {
    CRITICAL: "bg-red-500/15 border-red-500/30 text-red-400",
    HIGH:     "bg-orange-500/15 border-orange-500/30 text-orange-400",
    MEDIUM:   "bg-yellow-500/15 border-yellow-500/30 text-yellow-400",
    LOW:      "bg-blue-500/15 border-blue-500/30 text-blue-400",
  }[severity] || "bg-slate-500/15 border-slate-500/30 text-slate-400"

  return (
    <span className={`px-1.5 py-0.5 rounded border text-[9px] font-mono uppercase font-bold tracking-wider ${styles}`}>
      {severity}
    </span>
  )
}

function formatDate(ts) {
  if (!ts) return "—"
  const d = new Date(ts)
  if (isNaN(d.getTime())) return "—"
  return d.toLocaleString("fr-FR", {
    day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false,
  })
}

const BORDER = {
  CRITICAL: "border-red-500/60",
  HIGH:     "border-orange-500/60",
  MEDIUM:   "border-yellow-500/60",
  LOW:      "border-blue-500/60",
}

const ANOMALY_CFG = {
  CPU_SPIKE:              { icon: Cpu,         label: "CPU Spike",           color: "text-orange-400" },
  RAM_EXHAUSTION:         { icon: MemoryStick, label: "RAM Exhaustion",      color: "text-purple-400" },
  DISK_FULL:              { icon: HardDrive,   label: "Disque plein",        color: "text-yellow-400" },
  SUSPICIOUS_COMMAND:     { icon: Terminal,    label: "Commande suspecte",   color: "text-red-400"    },
  UNEXPECTED_ROOT_PROC:   { icon: Terminal,    label: "Processus root",      color: "text-red-400"    },
  PROCESS_OVERLOAD:       { icon: Cpu,         label: "Processus surchargé", color: "text-orange-400" },
  FILE_CHANGE:            { icon: FileText,    label: "Fichier modifié",     color: "text-cyan-400"   },
  SUSPICIOUS_CONNECTION:  { icon: Network,     label: "Connexion suspecte",  color: "text-red-400"    },
}

function AnomalyBody({ toast }) {
  switch (toast.anomaly_type) {
    case "PROCESS_OVERLOAD":
      return (
        <>
          <div className="text-slate-300 truncate">
            <span className="text-orange-300 font-semibold">{toast.process_name ?? "?"}</span>
            <span className="text-slate-500 mx-1">·</span>
            <span className="text-orange-400">CPU {toast.process_cpu}%</span>
            {toast.process_mem && (
              <span className="text-slate-500 ml-1">RAM {Number(toast.process_mem).toFixed(1)}%</span>
            )}
          </div>
          <div className="text-[10px] text-slate-500">
            pid={toast.process_pid}
            {toast.overload_cycles && ` · ${toast.overload_cycles} cycles`}
            {toast.process_user && ` · user=${toast.process_user}`}
          </div>
        </>
      )
    case "SUSPICIOUS_COMMAND":
    case "UNEXPECTED_ROOT_PROC":
      return (
        <>
          <div className="text-slate-300 truncate">
            <span className="text-red-300 font-semibold">{toast.process_name ?? "?"}</span>
            <span className="text-slate-500 mx-1">·</span>
            <span className="text-red-400">user={toast.process_user ?? "?"}</span>
          </div>
          {toast.process_cmd && (
            <div className="text-[10px] text-slate-500 truncate font-mono" title={toast.process_cmd}>
              $ {toast.process_cmd.slice(0, 60)}
            </div>
          )}
          <div className="text-[10px] text-slate-600">pid={toast.process_pid}</div>
        </>
      )
    case "FILE_CHANGE":
      return (
        <>
          <div className="text-slate-300 truncate font-mono text-[11px]" title={toast.file_path}>
            {toast.file_path ? toast.file_path.split("/").pop() : "fichier inconnu"}
          </div>
          <div className="text-[10px] text-slate-500 truncate">{toast.file_path}</div>
          <div className="text-[10px] flex gap-2">
            <span className={`font-semibold ${
              toast.change_type === "DELETED"   ? "text-red-400" :
              toast.change_type === "TRUNCATED" ? "text-orange-400" : "text-yellow-400"
            }`}>{toast.change_type}</span>
            {toast.old_size != null && (
              <span className="text-slate-600">{toast.old_size}B → {toast.new_size}B</span>
            )}
          </div>
        </>
      )
    case "SUSPICIOUS_CONNECTION":
      return (
        <>
          <div className="text-slate-300 truncate">
            <span className="text-slate-400">{toast.local_addr ?? "local"}</span>
            <span className="text-red-400 mx-1">→</span>
            <span className="text-red-300 font-semibold">{toast.remote_addr ?? "?"}</span>
          </div>
          <div className="text-[10px] text-slate-500">
            pid={toast.conn_pid ?? "?"} · {toast.conn_status ?? "—"}
          </div>
        </>
      )
    default:
      return (
        <div className="text-slate-400 text-[11px] truncate" title={toast.detail}>
          {toast.detail ?? "—"}
        </div>
      )
  }
}

function MonitorToast({ toast, onClose }) {
  const [visible, setVisible] = useState(true)
  const timerRef = useRef(null)

  // Extraction sécurisée de l'ID (MongoDB _id ou id normalisé)
  const toastId = toast.id || toast._id;

  useEffect(() => {
    // Relance du timer automatique de disparition
    timerRef.current = setTimeout(() => {
      setVisible(false)
      setTimeout(() => onClose(toastId), 300) // Attendre l'animation CSS d'opacité (300ms)
    }, 7000)

    return () => clearTimeout(timerRef.current)
  }, [toastId, onClose])

  const handleClose = () => {
    clearTimeout(timerRef.current)
    setVisible(false)
    setTimeout(() => onClose(toastId), 300)
  }

  const cfg      = ANOMALY_CFG[toast.anomaly_type] ?? { icon: ShieldAlert, label: toast.anomaly_type, color: "text-slate-400" }
  const Icon     = cfg.icon
  const severity = (toast.severity ?? "medium").toUpperCase()

  return (
    <div className={`pointer-events-auto w-full bg-slate-900/95 border
      ${BORDER[severity] || "border-gray-500/60"}
      rounded-lg p-3 shadow-2xl backdrop-blur-sm flex gap-3 items-start
      text-xs font-mono transition-all duration-300
      ${visible ? "opacity-100 translate-x-0" : "opacity-0 translate-x-full"}`}>
      
      <Icon className={`w-4 h-4 mt-0.5 shrink-0 animate-pulse ${cfg.color}`} />
      
      <div className="flex-1 min-w-0 space-y-1">
        <div className="flex items-center gap-2 flex-wrap">
          <Badge severity={severity} />
          <span className={`font-bold ${cfg.color}`}>{cfg.label}</span>
          <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-700/80
            text-slate-400 border border-slate-600/40 uppercase tracking-wider">monitor</span>
        </div>
        
        <div className="text-[10px] text-slate-400">
          <span className="text-slate-600">hôte : </span>
          <span className="text-cyan-400 font-semibold">
            {toast.agent_hostname ?? toast.ip_src ?? "—"}
          </span>
        </div>
        
        <AnomalyBody toast={toast} />
        
        <div className="text-[10px] text-slate-600">{formatDate(toast.detection_time)}</div>
      </div>
      
      <button onClick={handleClose} className="text-slate-500 hover:text-white transition-colors shrink-0">
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}

export function ToastMonitorContainer({ toasts, onClose }) {
  return (
    // Décalé vers le bas (mt-24) pour éviter les chevauchements potentiels avec d'autres toasts (ex: réseau)
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 w-80 pointer-events-none mt-24">
      {toasts.map(toast => (
        // Sécurisation de la clé de mapping React avec l'identifiant cumulé
        <MonitorToast key={toast.id || toast._id} toast={toast} onClose={onClose} />
      ))}
    </div>
  )
}