import { useState } from "react"
import {
  Settings,
  Cpu,
  MemoryStick,
  HardDrive,
  Bell,
  RefreshCw,
  Moon,
} from "lucide-react"

export function Paramètres() {
  const [local, setLocal] = useState({
    cpu: { warn: 70, critical: 85 },
    ram: { warn: 75, critical: 90 },
    disk: { warn: 80, critical: 95 },
  })

  const set = (metric, level, val) =>
    setLocal((p) => ({
      ...p,
      [metric]: {
        ...p[metric],
        [level]: Number(val),
      },
    }))

  return (
    <div className="flex flex-col gap-6 p-6 h-full overflow-y-auto w-full">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Settings className="w-5 h-5 text-red-500" />
        <div>
          <h1 className="text-lg font-semibold text-slate-800 dark:text-slate-200">
            Paramètres
          </h1>
          <p className="text-xs text-slate-500">
            Configuration générale de l'application.
          </p>
        </div>
      </div>

      {/* Cartes */}
      <div className="w-full min-w-0 flex-1 h-full p-6">

        {/* Monitoring */}
        <div className="rounded-2xl border border-slate-700/30 bg-slate-900/40 p-5">
          <h2 className="text-sm font-semibold text-slate-200 mb-4">
            Seuils de monitoring
          </h2>

          <div className="flex flex-col gap-5">
            {[
              { key: "cpu", label: "CPU", icon: Cpu },
              { key: "ram", label: "RAM", icon: MemoryStick },
              { key: "disk", label: "Disque", icon: HardDrive },
            ].map(({ key, label, icon: Icon }) => (
              <div key={key}>
                <div className="flex items-center gap-2 mb-2">
                  <Icon className="w-4 h-4 text-slate-500" />
                  <span className="text-sm text-slate-300">
                    {label}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <input
                    type="number"
                    value={local[key].warn}
                    onChange={(e) =>
                      set(key, "warn", e.target.value)
                    }
                    className="bg-slate-800 border border-slate-700 rounded-lg p-2 text-sm text-slate-200"
                    placeholder="Avertissement"
                  />

                  <input
                    type="number"
                    value={local[key].critical}
                    onChange={(e) =>
                      set(key, "critical", e.target.value)
                    }
                    className="bg-slate-800 border border-slate-700 rounded-lg p-2 text-sm text-slate-200"
                    placeholder="Critique"
                  />
                </div>

                {/* Aperçu */}
                <div className="flex h-2 mt-3 rounded-full overflow-hidden">
                  <div
                    className="bg-emerald-500"
                    style={{ width: `${local[key].warn}%` }}
                  />
                  <div
                    className="bg-yellow-500"
                    style={{
                      width: `${
                        local[key].critical -
                        local[key].warn
                      }%`,
                    }}
                  />
                  <div
                    className="bg-red-500 flex-1"
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bouton */}
      <div className="flex justify-end">
        <button
          className="px-5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold"
        >
          Enregistrer
        </button>
      </div>
    </div>
  )
}