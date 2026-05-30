import { BrowserRouter, Routes, Route } from "react-router-dom"
import { Layout }    from "./components/layout/Layout"
import { Dashboard } from "./views/Dashboard"

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/"        element={<Dashboard />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}