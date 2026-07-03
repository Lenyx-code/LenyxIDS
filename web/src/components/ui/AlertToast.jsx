// ui/AlertToast.jsx — Toasts alertes RÉSEAU uniquement (PORT_SCAN, BRUTE_FORCE, etc.)
// Les toasts monitoring sont dans AlertMonitorToast.jsx

import { useEffect, useRef, useState } from "react"
import { ShieldAlert, X } from "lucide-react"
import { Badge } from "./Badge"
// dans ui/AlertToast.jsx, remplace la définition locale par :
import { createToastId } from "../../utils/toastUtils"

let _counter = 0

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

function AlertToast({ toast, onClose }) {
  const [visible, setVisible] = useState(true)
  const timerRef = useRef(null)

  useEffect(() => {
    timerRef.current = setTimeout(() => {
      setVisible(false)
      setTimeout(() => onClose(toast.id), 300)
    }, 5000)
    return () => clearTimeout(timerRef.current)
  }, [toast.id, onClose])

  const handleClose = () => {
    clearTimeout(timerRef.current)
    setVisible(false)
    setTimeout(() => onClose(toast.id), 300)
  }

  return (
    <div className={`pointer-events-auto w-full bg-slate-900/95 border
      ${BORDER[toast.severity?.toUpperCase()] || "border-gray-500/60"}
      rounded-lg p-3 shadow-2xl backdrop-blur-sm flex gap-3 items-start
      text-xs font-mono transition-all duration-300
      ${visible ? "opacity-100 translate-x-0" : "opacity-0 translate-x-full"}`}>
      <ShieldAlert className="text-red-400 w-4 h-4 mt-0.5 shrink-0 animate-pulse" />
      <div className="flex-1 min-w-0 space-y-1">
        <div className="flex items-center gap-2 flex-wrap">
          <Badge severity={toast.severity} />
          <span className="text-red-400 font-bold">{toast.attack_type}</span>
        </div>
        <div className="text-slate-200 truncate">
          <span className="text-cyber-accent">{toast.ip_src}</span>
          <span className="text-slate-500 mx-1">→</span>
          <span>{toast.ip_dst}</span>
        </div>
        <div className="text-[10px] text-slate-500 flex justify-between">
          <span>{formatDate(toast.detection_time)}</span>
          {toast.port_dst && <span>Port : {toast.port_dst}</span>}
        </div>
      </div>
      <button onClick={handleClose} className="text-slate-500 hover:text-white transition-colors shrink-0">
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}

export function ToastContainer({ toasts, onClose }) {
  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 w-80 pointer-events-none">
      {toasts.map(toast => (
        <AlertToast key={toast.id} toast={toast} onClose={onClose} />
      ))}
    </div>
  )
}