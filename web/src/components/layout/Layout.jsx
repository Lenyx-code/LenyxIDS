import { useEffect } from "react"
import { Outlet } from "react-router-dom"
import { Sidebar } from "./Sidebar"
import { ToastContainer } from "../ui/AlertToast"
import { ToastMonitorContainer } from "../ui/AlertMonitorToast"
import { useSSEStore } from "../../store/sseStore"

export function Layout() {
  const toasts   = useSSEStore((state) => state.toasts)
  const closeToast = useSSEStore((state) => state.closeToast)
  const monitorAlerts = useSSEStore((state) => state.monitorAlerts)
  const closeMonitorAlertToast = useSSEStore((state) => state.closeMonitorAlertToast)
  const initRealtime = useSSEStore((state) => state.initRealtime)

  useEffect(() => {
    initRealtime()
    // pas de closeRealtime() ici : Layout vit pendant toute la durée de l'app,
    // on veut que les connexions persistent quelle que soit la route active
  }, [initRealtime])

  return (
    <div className="flex bg-cyber-bg min-h-screen">
      <Sidebar />
      <ToastContainer toasts={toasts} onClose={closeToast} />
      <ToastMonitorContainer toasts={monitorAlerts} onClose={closeMonitorAlertToast} />
      <main className="flex-1 ml-40 p-6 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}