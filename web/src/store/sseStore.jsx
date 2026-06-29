// src/store/sseStore.jsx
import {
  createContext, useContext, useState,
  useCallback, useRef, useEffect, useMemo,
} from "react"
import { SSE_URLS }          from "../services/api"
import { createToastId }     from "../utils/toastUtils"
import { normalizeProtocol } from "../utils/formatters"

const HISTORY_MAX = 60

const AlertContext        = createContext(null)
const PacketContext       = createContext(null)
const AlertMonitorContext = createContext(null)

const pushCapped = (arr, val) => {
  const next = [...(arr ?? []), val ?? 0]
  return next.length > HISTORY_MAX ? next.slice(-HISTORY_MAX) : next
}

export function SSEProvider({ children }) {
  // ── Alerts ──────────────────────────────────────────────────────
  const [toasts,    setToasts]    = useState([])
  const [alertConn, setAlertConn] = useState(false)

  // ── Monitor alerts ───────────────────────────────────────────────
  const [monitorToasts,    setMonitorToasts]    = useState([])
  const [alertMonitorConn, setAlertMonitorConn] = useState(false)

  // ── Hosts (métriques SSE + historique) ──────────────────────────
  const [monitorHosts,  setMonitorHosts]  = useState([])
  const [historyMap,    setHistoryMap]    = useState({}) // hostname → { cpu, ram, disk }
  const [hostsLoading,  setHostsLoading]  = useState(true)
  const [lastUpdate,    setLastUpdate]    = useState(null)

  // ── Packets ─────────────────────────────────────────────────────
  const [packets, setPackets] = useState([])
  const [pktConn, setPktConn] = useState(false)
  const pausedRef       = useRef(false)
  const packetBufferRef = useRef([])

  // helper : applique un snapshot host et met à jour l'historique
  const applyHostData = useCallback((d) => {
    const key = d.hostname
    if (!key) return
    setMonitorHosts(prev => {
      const i = prev.findIndex(h => h.hostname === key)
      if (i === -1) return [d, ...prev]
      const copy = [...prev]; copy[i] = d; return copy
    })
    setHistoryMap(prev => {
      const h = prev[key] ?? { cpu: [], ram: [], disk: [] }
      return {
        ...prev,
        [key]: {
          cpu:  pushCapped(h.cpu,  d.cpu_pct),
          ram:  pushCapped(h.ram,  d.ram_pct),
          disk: pushCapped(h.disk, d.disk_pct),
        },
      }
    })
    setLastUpdate(new Date())
  }, [])

  // ── SSE alertes IDS ─────────────────────────────────────────────
  useEffect(() => {
    let retry = null, es = null
    const connect = () => {
      es = new EventSource(SSE_URLS.alerts)
      es.onopen    = () => setAlertConn(true)
      es.onmessage = (e) => {
        try {
          const d = JSON.parse(e.data)
          if (d?.connected) return
          setToasts(prev => {
            if (d._id && prev.some(t => t._id === d._id)) return prev
            return [...prev.slice(-3), { ...d, id: createToastId() }]
          })
        } catch {}
      }
      es.onerror = () => { setAlertConn(false); es.close(); retry = setTimeout(connect, 3000) }
    }
    connect()
    return () => { clearTimeout(retry); es?.close() }
  }, [])

  // ── SSE métriques hosts ──────────────────────────────────────────
  useEffect(() => {
    let retry = null, es = null
    const connect = () => {
      es = new EventSource(SSE_URLS.monitoring)
      es.onopen    = () => setHostsLoading(false)
      es.onmessage = (e) => {
        try {
          const d = JSON.parse(e.data)
          if (d?.connected) return
          applyHostData(d)
        } catch {}
      }
      es.onerror = () => { es.close(); retry = setTimeout(connect, 3000) }
    }
    connect()
    return () => { clearTimeout(retry); es?.close() }
  }, [applyHostData])

  // ── SSE alertes monitoring ───────────────────────────────────────
  useEffect(() => {
    let retry = null, es = null
    const connect = () => {
      es = new EventSource(SSE_URLS.monitorAlerts)
      es.onopen    = () => setAlertMonitorConn(true)
      es.onmessage = (e) => {
        try {
          const d = JSON.parse(e.data)
          if (d?.connected) return
          setMonitorToasts(prev => {
            if (d._id && prev.some(t => t._id === d._id)) return prev
            return [...prev.slice(-20), { ...d, id: createToastId() }]
          })
        } catch {}
      }
      es.onerror = () => { setAlertMonitorConn(false); es.close(); retry = setTimeout(connect, 3000) }
    }
    connect()
    return () => { clearTimeout(retry); es?.close() }
  }, [])

  // ── SSE paquets ──────────────────────────────────────────────────
  useEffect(() => {
    let retry = null, interval = null, es = null
    const connect = () => {
      es = new EventSource(SSE_URLS.packets)
      es.onopen    = () => setPktConn(true)
      es.onmessage = (e) => {
        if (pausedRef.current) return
        try {
          const d = JSON.parse(e.data)
          if (d?.connected) return
          packetBufferRef.current.unshift({ ...d, protocol: normalizeProtocol(d.protocol) })
        } catch {}
      }
      es.onerror = () => { setPktConn(false); es.close(); retry = setTimeout(connect, 3000) }
    }
    connect()
    interval = setInterval(() => {
      if (packetBufferRef.current.length === 0) return
      setPackets(prev => {
        const combined = [...packetBufferRef.current, ...prev]
        packetBufferRef.current = []
        return combined.slice(0, 200)
      })
    }, 400)
    return () => { clearTimeout(retry); clearInterval(interval); es?.close() }
  }, [])

  // ── Callbacks ────────────────────────────────────────────────────
  const closeToast        = useCallback((id) => setToasts(p => p.filter(t => t.id !== id)), [])
  const closeMonitorToast = useCallback((id) => setMonitorToasts(p => p.filter(t => t.id !== id)), [])
  const setPaused         = useCallback((v)  => { pausedRef.current = v }, [])
  const clearPackets      = useCallback(()   => setPackets([]), [])

  // ── Context values ───────────────────────────────────────────────
  const alertValue = useMemo(() => ({ toasts, alertConn, closeToast }),
    [toasts, alertConn, closeToast])

  const packetValue = useMemo(() => ({ packets, pktConn, setPaused, clearPackets }),
    [packets, pktConn, setPaused, clearPackets])

  const monitorValue = useMemo(() => ({
    monitorHosts, historyMap, hostsLoading, lastUpdate,
    monitorToasts, alertMonitorConn,
    closeMonitorToast, applyHostData,
  }), [monitorHosts, historyMap, hostsLoading, lastUpdate,
      monitorToasts, alertMonitorConn, closeMonitorToast, applyHostData])

  return (
    <AlertContext.Provider value={alertValue}>
      <AlertMonitorContext.Provider value={monitorValue}>
        <PacketContext.Provider value={packetValue}>
          {children}
        </PacketContext.Provider>
      </AlertMonitorContext.Provider>
    </AlertContext.Provider>
  )
}

export const useAlertStore        = () => useContext(AlertContext)
export const useAlertMonitorStore = () => useContext(AlertMonitorContext)
export const usePacketStore       = () => useContext(PacketContext)
export const useSSEStore          = () => ({
  ...(useContext(AlertContext)        ?? {}),
  ...(useContext(AlertMonitorContext) ?? {}),
  ...(useContext(PacketContext)       ?? {}),
})