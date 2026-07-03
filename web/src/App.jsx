import { BrowserRouter, Routes, Route } from "react-router-dom"
import { Layout }    from "./components/layout/Layout"
import { Dashboard } from "./views/Dashboard"
import { Alerts }    from "./views/Alerts"
import { Reports } from "./views/Reports"
import { Monitoring } from "./views/Monitoring"
import { Analyse } from "./views/Analyse"
import { Paramètres } from "./views/Settings"

export default function App() {
  return (
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
           <Route path="/"        element={<Dashboard />} />
           <Route path="/alerts"  element={<Alerts />}    />
           <Route path="/reports"  element={<Reports />}    />
           <Route path="/analyses"  element={<Analyse />}    />
           <Route path="/monitoring"  element={<Monitoring />}    />
           <Route path="/settings"  element={<Paramètres/>}    />
          </Route>
        </Routes>
      </BrowserRouter>
  )
}