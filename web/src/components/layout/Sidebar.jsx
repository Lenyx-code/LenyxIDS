import { NavLink } from "react-router-dom"
import { LayoutDashboard, Network, ShieldAlert, FileText, Shield, Settings, Monitor, Radar} from "lucide-react"

const NAV_ITEMS = [
  { to: "/",        icon: LayoutDashboard, label: "Dashboard"   },
  { to: "/alerts",  icon: ShieldAlert,     label: "Alertes"  },
  { to: "/reports", icon: FileText,        label: "Rapports"     },
  { to: "/analyses", icon: Radar,          label: "Analyses"     },
  { to: "/monitoring", icon: Monitor,      label: "Monitoring"     },
  { to: "/settings", icon: Settings,       label: "Paramètres"     },
]

export function Sidebar() {
  return (
    // w-[192px] explicite — correspond au ml-[192px] du Layout
    <aside className="w-[192px] h-screen bg-cyber-surface border-r border-cyber-border flex flex-col fixed left-0 top-0 z-10">

      <div className="px-4 py-5 border-b border-cyber-border">
        <div className="flex items-center gap-2.5">
          <Shield className="text-cyber-accent w-5 h-5 shrink-0" />
          <div className="min-w-0">
            <p className="text-cyber-accent font-mono font-bold text-xs leading-tight">CYBER IDS</p>
            <p className="text-slate-600 text-[10px] font-mono leading-tight">Cybersecurity</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-3 space-y-0.5">
        {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              `flex items-center gap-2.5 px-2.5 py-2 rounded font-mono text-xs transition-all ${
                isActive
                  ? "bg-cyber-accent/10 text-cyber-accent border border-cyber-accent/20  p-5 mt-5"
                  : "text-slate-500 hover:text-slate-200 hover:bg-slate-800/60  p-5 mt-5"
              }`
            }
          >
            <Icon className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="px-4 py-3 border-t border-cyber-border">
        <p className="text-slate-700 text-[9px] font-mono text-center">PME Cameroun — v1.0.0</p>
      </div>
    </aside>
  )
}