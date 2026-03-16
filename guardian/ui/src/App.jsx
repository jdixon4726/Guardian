import { Routes, Route, NavLink } from 'react-router-dom'
import { useTheme } from './hooks/useTheme'
import { useApi } from './hooks/useApi'
import CommandCenter from './views/CommandCenter'
import ActorIntelligence from './views/ActorIntelligence'
import AutomationGraph from './views/AutomationGraph'
import BlastRadius from './views/BlastRadius'
import FeedbackAccuracy from './views/FeedbackAccuracy'
import Reconciliation from './views/Reconciliation'

function App() {
  const { theme, toggle } = useTheme()
  const { data: health } = useApi('/v1/health', { autoRefresh: 30000 })

  const healthStatus = health?.status || 'unknown'
  const shadowMode = health?.shadow_mode || false

  return (
    <div className="app">
      <nav className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-logo">
            Guardian
            <span>Behavioral Governance Engine</span>
          </div>
          <div className="health-badge">
            <div className={`health-dot ${healthStatus === 'ok' ? (shadowMode ? 'shadow' : 'ok') : 'error'}`} />
            {healthStatus === 'ok' ? (shadowMode ? 'Shadow Mode' : 'Operational') : 'Offline'}
          </div>
        </div>

        <ul className="sidebar-nav">
          <li><NavLink to="/" end>Command Center</NavLink></li>
          <li><NavLink to="/actors">Actor Intelligence</NavLink></li>
          <li><NavLink to="/graph">Automation Graph</NavLink></li>
          <li><NavLink to="/blast-radius">Blast Radius</NavLink></li>
          <li><NavLink to="/feedback">Feedback & Accuracy</NavLink></li>
          <li><NavLink to="/reconciliation">Reconciliation</NavLink></li>
        </ul>

        <div className="sidebar-footer">
          <button className="theme-toggle" onClick={toggle}>
            {theme === 'dark' ? '\u2600\uFE0F' : '\uD83C\uDF19'} {theme === 'dark' ? 'Light Mode' : 'Dark Mode'}
          </button>
        </div>
      </nav>

      <main className="main-content">
        <Routes>
          <Route path="/" element={<CommandCenter />} />
          <Route path="/actors" element={<ActorIntelligence />} />
          <Route path="/graph" element={<AutomationGraph />} />
          <Route path="/blast-radius" element={<BlastRadius />} />
          <Route path="/feedback" element={<FeedbackAccuracy />} />
          <Route path="/reconciliation" element={<Reconciliation />} />
        </Routes>
      </main>
    </div>
  )
}

export default App
