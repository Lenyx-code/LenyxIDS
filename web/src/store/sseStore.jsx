import { create } from "zustand"
import { SSE_URLS } from "../services/api"
import { createToastId } from "../utils/toastUtils"
import { normalizeProtocol } from "../utils/formatters"

const MAX_PACKETS = 200
const MAX_TOASTS  = 4
const HISTORY_MAX = 60
const PACKET_FLUSH_MS = 150


let esPackets        = null
let esAlerts         = null
let esMonitorAlerts  = null
let esMonitoring     = null

let _pktCounter = 0

export const useSSEStore = create((set, get) => ({
  //PACKETS
  packets: [],
  pktConn: false,
  paused: false,

  addPackets: (newPackets) =>
    set((state) => {
      if (state.paused || newPackets.length === 0) return state
      const normalized = newPackets.map((p) => ({
        ...p,
        protocol: normalizeProtocol(p.protocol),
        _cid: p._id ?? `pkt_${++_pktCounter}`,
      }))
      return {
        packets: [...normalized.reverse(), ...state.packets].slice(0, MAX_PACKETS),
      }
    }),

  // Conservé pour compat / usage ponctuel hors flux SSE à haut débit
  addPacket: (packet) => get().addPackets([packet]),

  clearPackets: () => set({ packets: [] }),
  setPktConn:   (value) => set({ pktConn: value }),
  setPaused:    (value) => set({ paused: value }),

  // ALERTES RÉSEAU
  toasts: [],
  alertConn: false,

  addToast: (toast) =>
    set((state) => {
      if (toast._id && state.toasts.some((t) => t._id === toast._id)) return state
      return {
        toasts: [
          ...state.toasts.slice(-MAX_TOASTS + 1),
          { ...toast, id: createToastId() },
        ],
      }
    }),

  closeToast: (id) =>
    set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) })),

  setAlertConn: (value) => set({ alertConn: value }),

  //  ALERTES MONITORING (anomalies) 
  monitorAlerts: [],
  monitorAlertConn: false,

  addMonitorAlert: (alert) =>
    set((state) => {
      if (alert._id && state.monitorAlerts.some((t) => t._id === alert._id)) return state
      return {
        monitorAlerts: [
          ...state.monitorAlerts.slice(-MAX_TOASTS + 1),
          { ...alert, id: createToastId() },
        ],
      }
    }),

  closeMonitorAlertToast: (id) =>
    set((state) => ({ monitorAlerts: state.monitorAlerts.filter((t) => t.id !== id) })),

  setMonitorAlertConn: (value) => set({ monitorAlertConn: value }),

  //  HOSTS / MÉTRIQUES 
  hosts: [],
  historyMap: {},
  lastUpdate: null,

  // Utilisé par le fetch REST (liste complète) — fusionne dans l'historique existant
  setHosts: (hosts) =>
    set((state) => {
      const historyMap = { ...state.historyMap }
      const push = (arr, val) => {
        const a = [...arr, val ?? 0]
        return a.length > HISTORY_MAX ? a.slice(-HISTORY_MAX) : a
      }
      hosts.forEach((h) => {
        const key = h.hostname ?? h._id
        const old = historyMap[key] ?? { cpu: [], ram: [], disk: [] }
        historyMap[key] = {
          cpu:  push(old.cpu,  h.cpu_pct),
          ram:  push(old.ram,  h.ram_pct),
          disk: push(old.disk, h.disk_pct),
        }
      })
      return { hosts, historyMap, lastUpdate: new Date() }
    }),

  // Utilisé par le flux SSE (une machine à la fois)
  updateHost: (host) =>
    set((state) => {
      const key = host.hostname ?? host._id
      const idx = state.hosts.findIndex((h) => (h.hostname ?? h._id) === key)
      const hosts =
        idx === -1
          ? [...state.hosts, host]
          : state.hosts.map((h) => ((h.hostname ?? h._id) === key ? { ...h, ...host } : h))

      const old = state.historyMap[key] ?? { cpu: [], ram: [], disk: [] }
      const push = (arr, val) => {
        const a = [...arr, val ?? 0]
        return a.length > HISTORY_MAX ? a.slice(-HISTORY_MAX) : a
      }

      return {
        hosts,
        lastUpdate: new Date(),
        historyMap: {
          ...state.historyMap,
          [key]: {
            cpu:  push(old.cpu,  host.cpu_pct),
            ram:  push(old.ram,  host.ram_pct),
            disk: push(old.disk, host.disk_pct),
          },
        },
      }
    }),

  initRealtime: () => {
    if (!esPackets) {
      let buffer = []
      let flushTimer = null

      const flush = () => {
        flushTimer = null
        if (buffer.length === 0) return
        const batch = buffer
        buffer = []
        get().addPackets(batch)
      }

      esPackets = new EventSource(SSE_URLS.packets)
      esPackets.onopen  = () => set({ pktConn: true })
      esPackets.onerror = () => set({ pktConn: false })
      esPackets.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data)
          if (data?.connected) return   // ignore le message de handshake SSE
          buffer.push(data)
          if (!flushTimer) flushTimer = setTimeout(flush, PACKET_FLUSH_MS)
        } catch {}
      }
    }

    if (!esAlerts) {
      esAlerts = new EventSource(SSE_URLS.alerts)
      esAlerts.onopen  = () => set({ alertConn: true })
      esAlerts.onerror = () => set({ alertConn: false })
      esAlerts.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data)
          if (data?.connected) return   // ignore le message de handshake SSE
          get().addToast(data)
        } catch {}
      }
    }

    if (!esMonitorAlerts) {
      esMonitorAlerts = new EventSource(SSE_URLS.monitorAlerts)
      esMonitorAlerts.onopen  = () => set({ monitorAlertConn: true })
      esMonitorAlerts.onerror = () => set({ monitorAlertConn: false })
      esMonitorAlerts.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data)
          if (data?.connected) return   // ignore le message de handshake SSE
          get().addMonitorAlert(data)
        } catch {}
      }
    }

    if (!esMonitoring) {
      esMonitoring = new EventSource(SSE_URLS.monitoring)
      esMonitoring.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data)
          if (data?.connected) return   // ignore le message de handshake SSE
          get().updateHost(data)
        } catch {}
      }
    }
  },

  closeRealtime: () => {
    esPackets?.close();       esPackets = null
    esAlerts?.close();        esAlerts = null
    esMonitorAlerts?.close(); esMonitorAlerts = null
    esMonitoring?.close();    esMonitoring = null
    set({ pktConn: false, alertConn: false, monitorAlertConn: false })
  },
}))