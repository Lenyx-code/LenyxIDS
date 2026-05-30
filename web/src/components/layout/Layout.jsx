import { Sidebar } from "./Sidebar"
import { Outlet }  from "react-router-dom"

export function Layout() {
  return (
    <div className="flex bg-cyber-bg min-h-screen">
      <Sidebar />
      <main className="flex-1 ml-48  pr-0 overflow-auto min-w-0">
        <Outlet />
      </main>
    </div>
  )
}