import { Outlet }                 from "react-router-dom"
import { Sidebar }                from "./Sidebar"
import { ToastContainer }         from "../ui/AlertToast"
import { ToastMonitorContainer }  from "../ui/AlertMonitorToast"
import { useAlertStore }          from "../../store/sseStore"
import { useAlertMonitorStore }   from "../../store/sseStore"

export function Layout() {
  const { toasts,        closeToast        } = useAlertStore()
  const { monitorToasts, closeMonitorToast } = useAlertMonitorStore()

  return (
    <div className="flex bg-cyber-bg min-h-screen">
      <Sidebar />

      {/* Toasts alertes réseau (rouge) */}
      <ToastContainer        toasts={toasts}        onClose={closeToast}        />

      {/* Toasts alertes monitoring (orange) */}
      <ToastMonitorContainer toasts={monitorToasts} onClose={closeMonitorToast} />

      <main className="flex-1 ml-40 p-6 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}