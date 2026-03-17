import { useState } from 'react'
import { Routes, Route, NavLink } from 'react-router-dom'
import { useTheme } from './hooks/useTheme'
import { useApi } from './hooks/useApi'
import Heartbeat from './components/Heartbeat'
import CommandCenter from './views/CommandCenter'
import ActorIntelligence from './views/ActorIntelligence'
import AutomationGraph from './views/AutomationGraph'
import BlastRadius from './views/BlastRadius'
import FeedbackAccuracy from './views/FeedbackAccuracy'
import Reconciliation from './views/Reconciliation'
import ThreatIntel from './views/ThreatIntel'
import Onboarding from './views/Onboarding'
import Compliance from './views/Compliance'

function NavGroup({ label, children }) {
  return (
    <li className="nav-group">
      <div className="nav-group-label">{label}</div>
      <ul className="nav-group-items">{children}</ul>
    </li>
  )
}

function App() {
  const { theme, toggle } = useTheme()
  const { data: health } = useApi('/v1/health', { autoRefresh: 15000 })
  const [sidebarOpen, setSidebarOpen] = useState(true)

  const healthStatus = health?.status || 'unknown'
  const shadowMode = health?.shadow_mode || false

  return (
    <div className="app">
      {/* Mobile hamburger */}
      <button
        className="sidebar-toggle"
        onClick={() => setSidebarOpen(!sidebarOpen)}
        aria-label="Toggle navigation"
      >
        {sidebarOpen ? '\u2715' : '\u2630'}
      </button>

      <nav className={`sidebar ${sidebarOpen ? '' : 'sidebar-collapsed'}`}>
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <span className="logo-icon">&#9678;</span> Guardian
            <span>Behavioral Governance Engine</span>
          </div>
          <div className="health-badge">
            <div className={`health-dot ${healthStatus === 'ok' ? (shadowMode ? 'shadow' : 'ok') : 'error'}`} />
            {healthStatus === 'ok' ? (shadowMode ? 'Shadow Mode' : 'Operational') : 'Offline'}
          </div>
        </div>

        <ul className="sidebar-nav">
          {/* Operations */}
          <NavGroup label="Operations">
            <li><NavLink to="/" end>&#9670; Command Center</NavLink></li>
            <li><NavLink to="/actors">&#9673; Actor Intelligence</NavLink></li>
            <li><NavLink to="/reconciliation">&#9638; Reconciliation</NavLink></li>
          </NavGroup>

          {/* Intelligence */}
          <NavGroup label="Intelligence">
            <li><NavLink to="/graph">&#9700; Automation Graph</NavLink></li>
            <li><NavLink to="/blast-radius">&#9681; Blast Radius</NavLink></li>
            <li><NavLink to="/threat-intel">&#9888; Threat Intel</NavLink></li>
          </NavGroup>

          {/* Governance */}
          <NavGroup label="Governance">
            <li><NavLink to="/compliance">&#9745; Compliance</NavLink></li>
            <li><NavLink to="/feedback">&#10003; Feedback</NavLink></li>
            <li><NavLink to="/onboard">&#9881; Setup</NavLink></li>
          </NavGroup>
        </ul>

        <div className="sidebar-footer">
          <Heartbeat />
          <button className="theme-toggle" onClick={toggle} style={{ marginTop: 8 }}>
            {theme === 'dark' ? '\u2600\uFE0F' : '\uD83C\uDF19'} {theme === 'dark' ? 'Light Mode' : 'Dark Mode'}
          </button>
        </div>
      </nav>

      <main className={`main-content ${sidebarOpen ? '' : 'main-expanded'}`}>
        <Routes>
          <Route path="/" element={<CommandCenter />} />
          <Route path="/actors" element={<ActorIntelligence />} />
          <Route path="/graph" element={<AutomationGraph />} />
          <Route path="/blast-radius" element={<BlastRadius />} />
          <Route path="/feedback" element={<FeedbackAccuracy />} />
          <Route path="/reconciliation" element={<Reconciliation />} />
          <Route path="/threat-intel" element={<ThreatIntel />} />
          <Route path="/compliance" element={<Compliance />} />
          <Route path="/onboard" element={<Onboarding />} />
        </Routes>
      </main>
    </div>
  )
}

export default App
