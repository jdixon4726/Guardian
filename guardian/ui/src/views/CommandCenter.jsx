import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useApi, postApi } from '../hooks/useApi'
import DecisionCard from '../components/DecisionCard'
import RiskGauge from '../components/RiskGauge'
import RiskPulse from '../components/RiskPulse'
import { SkeletonCard, SkeletonStats } from '../components/Skeleton'

// ── Relative time formatter ─────────────────────────────────────────────────
function relativeTime(ts) {
  if (!ts) return '—'
  const now = Date.now()
  const then = new Date(ts).getTime()
  const diffMs = now - then
  if (diffMs < 0) return 'just now'
  const seconds = Math.floor(diffMs / 1000)
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

// ── Simulation Mode Banner ──────────────────────────────────────────────────
function SimulationBanner() {
  return (
    <div style={{
      background: 'linear-gradient(90deg, rgba(210, 153, 11, 0.12), rgba(210, 153, 11, 0.06))',
      border: '1px solid rgba(210, 153, 11, 0.25)',
      borderRadius: 6,
      padding: '8px 16px',
      marginBottom: 16,
      display: 'flex',
      alignItems: 'center',
      gap: 8,
      fontSize: 12,
      color: 'var(--yellow)',
      fontFamily: 'var(--mono)',
    }}>
      <span style={{ fontSize: 14 }}>&#9888;</span>
      <span>
        Simulation Mode Active — Data shown is from attack scenario replays, not live production telemetry.
      </span>
    </div>
  )
}

// ── System Observability Panel ──────────────────────────────────────────────
function SystemObservability() {
  const { data, loading } = useApi('/v1/system/status', { autoRefresh: 10000 })

  const metrics = [
    { label: 'Events Ingested', key: 'events_ingested', fallback: '—' },
    { label: 'Active Actors', key: 'active_actors', fallback: '—' },
    { label: 'Connected Systems', key: 'connected_systems', fallback: '—' },
    { label: 'Graph Nodes Tracked', key: 'graph_nodes_tracked', fallback: '—' },
  ]

  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{
        fontSize: 11,
        textTransform: 'uppercase',
        letterSpacing: 0.8,
        color: 'var(--text-muted)',
        marginBottom: 8,
        fontWeight: 600,
      }}>
        System Status
      </div>
      <div style={{ display: 'flex', gap: 10 }}>
        {metrics.map(m => (
          <div key={m.key} className="stat-card" style={{
            flex: 1,
            padding: '10px 14px',
            minWidth: 0,
          }}>
            <div className="stat-value" style={{
              fontSize: 20,
              color: 'var(--text)',
              fontVariantNumeric: 'tabular-nums',
              opacity: loading && !data ? 0.3 : 1,
            }}>
              {data?.[m.key] != null ? data[m.key].toLocaleString() : m.fallback}
            </div>
            <div className="stat-label" style={{ fontSize: 11 }}>{m.label}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Connected Systems Panel ─────────────────────────────────────────────────
function ConnectedSystems() {
  const { data, loading } = useApi('/v1/systems/connected', { autoRefresh: 30000 })

  if (loading && !data) return null

  const systems = data?.systems || data || []
  if (!Array.isArray(systems) || systems.length === 0) return null

  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{
        fontSize: 11,
        textTransform: 'uppercase',
        letterSpacing: 0.8,
        color: 'var(--text-muted)',
        marginBottom: 8,
        fontWeight: 600,
      }}>
        Connected Systems
      </div>
      <div style={{
        display: 'flex',
        gap: 10,
        overflowX: 'auto',
        paddingBottom: 4,
        scrollbarWidth: 'thin',
      }}>
        {systems.map((sys, i) => {
          const isActive = (sys.status || '').toLowerCase() === 'active'
          return (
            <div key={sys.name || i} className="card" style={{
              padding: '10px 14px',
              minWidth: 160,
              flexShrink: 0,
              borderLeft: `3px solid ${isActive ? 'var(--green)' : 'var(--border)'}`,
            }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                marginBottom: 6,
              }}>
                <span style={{
                  width: 7,
                  height: 7,
                  borderRadius: '50%',
                  background: isActive ? 'var(--green)' : 'var(--text-muted)',
                  display: 'inline-block',
                  flexShrink: 0,
                }} />
                <span style={{
                  fontSize: 13,
                  fontWeight: 600,
                  color: 'var(--text)',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}>
                  {sys.name}
                </span>
              </div>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'baseline',
                fontSize: 11,
                color: 'var(--text-muted)',
              }}>
                <span style={{ fontVariantNumeric: 'tabular-nums' }}>
                  {sys.event_count != null ? `${sys.event_count.toLocaleString()} events` : '—'}
                </span>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 10 }}>
                  {relativeTime(sys.last_event)}
                </span>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Empty state with demo data loader ────────────────────────────────────────
function EmptyState() {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)

  const loadDemo = async () => {
    setLoading(true)
    try {
      const res = await postApi('/v1/ingest/demo', {})
      setResult(res)
      // Reload after short delay to show new data
      setTimeout(() => window.location.reload(), 1500)
    } catch (err) {
      setResult({ error: err.message })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card" style={{ textAlign: 'center', padding: '48px 32px' }}>
      <div style={{ fontSize: 40, marginBottom: 12, opacity: 0.3 }}>&#9678;</div>
      <h3 style={{ margin: '0 0 8px', color: 'var(--text)' }}>No decisions yet</h3>
      <p style={{ color: 'var(--text-muted)', margin: '0 0 24px', maxWidth: 420, marginInline: 'auto', lineHeight: 1.5 }}>
        Guardian is running but hasn't evaluated any actions yet.
        Load demo data to see 10 real-world attack scenarios (Stryker wiper, SolarWinds, Uber breach, and more) evaluated through the full pipeline.
      </p>
      <button
        onClick={loadDemo}
        disabled={loading}
        style={{
          background: 'var(--accent)',
          color: '#fff',
          border: 'none',
          borderRadius: 6,
          padding: '10px 24px',
          fontSize: 14,
          fontWeight: 600,
          cursor: loading ? 'wait' : 'pointer',
          opacity: loading ? 0.6 : 1,
        }}
      >
        {loading ? 'Loading scenarios...' : 'Load Demo Data'}
      </button>
      {result && !result.error && (
        <p style={{ color: 'var(--green)', marginTop: 12, fontSize: 13 }}>
          Loaded {result.total_events} events from {result.scenarios_run?.length || 0} scenarios. Refreshing...
        </p>
      )}
      {result?.error && (
        <p style={{ color: 'var(--red)', marginTop: 12, fontSize: 13 }}>
          Error: {result.error}
        </p>
      )}
    </div>
  )
}

// ── Severity simplification: 3 tiers ────────────────────────────────────────
// Research: 3 levels maximum. Critical (needs action), Warning (monitor), Info.
function classifySeverity(decision) {
  if (decision.decision === 'block') return 'critical'
  if (decision.decision === 'require_review' && decision.risk_score >= 0.5) return 'critical'
  if (decision.decision === 'require_review') return 'warning'
  return 'info'
}

// ── System classification helper ────────────────────────────────────────────
function classifySystem(actorName) {
  const name = (actorName || '').toLowerCase()
  if (name.includes('terraform')) return 'Terraform'
  if (name.includes('argocd') || name.includes('k8s') || name.includes('cert-') || name.includes('kubernetes')) return 'Kubernetes'
  if (name.includes('github') || name.includes('ci-') || name.includes('gitlab') || name.includes('jenkins') || name.includes('circleci')) return 'CI/CD'
  if (name.includes('datadog') || name.includes('monitor') || name.includes('prometheus') || name.includes('grafana')) return 'Monitoring'
  if (name.includes('mcp-') || name.includes('a2a-') || name.includes('ai-')) return 'AI Agents'
  if (name.includes('intune') || name.includes('jamf')) return 'MDM/UEM'
  if (name.includes('aws-')) return 'AWS'
  if (name.includes('entra') || name.includes('okta') || name.includes('azure-ad')) return 'Identity'
  if (name.includes('data-pipeline') || name.includes('data-')) return 'Data'
  return 'Other'
}

// ── Action Items: "What needs attention right now?" ─────────────────────────
function ActionItems({ decisions, onNavigateToActor }) {
  const items = useMemo(() => {
    if (!decisions) return []
    const actions = []

    // Blocked decisions need review
    const blocks = decisions.filter(d => d.decision === 'block')
    if (blocks.length > 0) {
      const actors = [...new Set(blocks.map(d => d.actor_name))]
      actions.push({
        severity: 'critical',
        icon: '\u2718',
        title: `${blocks.length} blocked action${blocks.length > 1 ? 's' : ''} need review`,
        desc: `Actor${actors.length > 1 ? 's' : ''}: ${actors.slice(0, 3).join(', ')}${actors.length > 3 ? ` +${actors.length - 3} more` : ''}`,
        cta: 'Review',
        actor: actors[0],
      })
    }

    // High-risk reviews
    const highRiskReviews = decisions.filter(d => d.decision === 'require_review' && d.risk_score >= 0.5)
    if (highRiskReviews.length > 0) {
      actions.push({
        severity: 'critical',
        icon: '\u26A0',
        title: `${highRiskReviews.length} high-risk action${highRiskReviews.length > 1 ? 's' : ''} awaiting review`,
        desc: `Risk scores: ${highRiskReviews.map(d => d.risk_score.toFixed(2)).join(', ')}`,
        cta: 'Investigate',
        actor: highRiskReviews[0].actor_name,
      })
    }

    // Drift detected
    const drifting = decisions.filter(d => d.drift_score && d.drift_score > 0.3)
    if (drifting.length > 0) {
      const actors = [...new Set(drifting.map(d => d.actor_name))]
      actions.push({
        severity: 'warning',
        icon: '\u2248',
        title: `Behavioral drift detected in ${actors.length} actor${actors.length > 1 ? 's' : ''}`,
        desc: actors.slice(0, 3).join(', '),
        cta: 'Analyze',
        actor: actors[0],
      })
    }

    return actions.slice(0, 3) // Max 3 action items
  }, [decisions])

  if (items.length === 0) {
    return (
      <div className="action-items">
        <div className="action-item" style={{ cursor: 'default', borderLeft: '3px solid var(--green)' }}>
          <div className="action-icon" style={{ background: 'rgba(63, 185, 80, 0.15)', fontSize: 16 }}>{'\u2714'}</div>
          <div className="action-text">
            <div className="action-title" style={{ color: 'var(--green)' }}>All clear</div>
            <div className="action-desc">No actions require your attention right now.</div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="action-items">
      {items.map((item, i) => (
        <div
          key={i}
          className={`action-item ${item.severity}`}
          onClick={() => item.actor && onNavigateToActor(item.actor)}
        >
          <div className="action-icon">{item.icon}</div>
          <div className="action-text">
            <div className="action-title">{item.title}</div>
            <div className="action-desc">{item.desc}</div>
          </div>
          <button className="action-cta">{item.cta} &rarr;</button>
        </div>
      ))}
    </div>
  )
}

// ── System filter tabs ──────────────────────────────────────────────────────
function SystemTabs({ decisions, activeSystem, onSelect }) {
  const systems = useMemo(() => {
    if (!decisions) return []
    const counts = {}
    decisions.forEach(d => {
      const system = classifySystem(d.actor_name)
      counts[system] = (counts[system] || 0) + 1
    })
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .map(([name, count]) => ({ name, count }))
  }, [decisions])

  return (
    <div className="system-tabs">
      <button
        className={`system-tab ${!activeSystem ? 'active' : ''}`}
        onClick={() => onSelect(null)}
      >
        All<span className="tab-count">{decisions?.length || 0}</span>
      </button>
      {systems.map(s => (
        <button
          key={s.name}
          className={`system-tab ${activeSystem === s.name ? 'active' : ''}`}
          onClick={() => onSelect(s.name)}
        >
          {s.name}<span className="tab-count">{s.count}</span>
        </button>
      ))}
    </div>
  )
}

// ── Main Command Center ─────────────────────────────────────────────────────
export default function CommandCenter() {
  const navigate = useNavigate()
  const [actor, setActor] = useState('')
  const [decisionFilter, setDecisionFilter] = useState('')
  const [activeSystem, setActiveSystem] = useState(null)
  const [expanded, setExpanded] = useState(null)

  const params = new URLSearchParams()
  params.set('limit', '200')
  if (actor) params.set('actor', actor)
  if (decisionFilter) params.set('decision', decisionFilter)

  const { data, loading, error } = useApi(
    `/v1/decisions/recent?${params.toString()}`,
    { autoRefresh: 15000 }
  )

  // Compute stats
  const stats = useMemo(() => {
    if (!data?.decisions) return null
    const d = data.decisions
    return {
      total: d.length,
      critical: d.filter(x => classifySeverity(x) === 'critical').length,
      warning: d.filter(x => classifySeverity(x) === 'warning').length,
      info: d.filter(x => classifySeverity(x) === 'info').length,
      avgRisk: d.length > 0 ? d.reduce((s, x) => s + x.risk_score, 0) / d.length : 0,
    }
  }, [data])

  // Filter by system tab
  const filteredDecisions = useMemo(() => {
    if (!data?.decisions) return []
    let decisions = data.decisions

    if (activeSystem) {
      decisions = decisions.filter(d => classifySystem(d.actor_name) === activeSystem)
    }

    // Sort: critical first, then warning, then info, then by time
    return decisions.sort((a, b) => {
      const sa = classifySeverity(a)
      const sb = classifySeverity(b)
      const order = { critical: 0, warning: 1, info: 2 }
      if (order[sa] !== order[sb]) return order[sa] - order[sb]
      return 0 // preserve chronological within same severity
    })
  }, [data, activeSystem])

  const navigateToActor = (actorName) => {
    navigate(`/actors?name=${encodeURIComponent(actorName)}`)
  }

  return (
    <div>
      {/* Simulation Mode Banner */}
      <SimulationBanner />

      <div className="page-header">
        <h1>Command Center</h1>
        <p>Real-time governance decision feed</p>
      </div>

      {/* System Observability — high-level metrics */}
      <SystemObservability />

      {/* Connected Systems — horizontal scroll */}
      <ConnectedSystems />

      {/* Action Items — "What needs my attention?" */}
      {data && (
        <ActionItems
          decisions={data.decisions}
          onNavigateToActor={navigateToActor}
        />
      )}

      {/* Summary stats — 3-tier severity */}
      {loading && !data ? (
        <SkeletonStats count={5} />
      ) : stats && (
        <div style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
          <div className="stat-card" style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 12 }}>
            <RiskGauge score={stats.avgRisk} size={52} strokeWidth={5} />
            <div>
              <div className="stat-label">Avg Risk</div>
              <div style={{ fontSize: 13, fontVariantNumeric: 'tabular-nums' }}>{stats.total} decisions</div>
            </div>
          </div>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-value" style={{ color: 'var(--red)', fontSize: 24 }}>{stats.critical}</div>
            <div className="stat-label">Critical</div>
          </div>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-value" style={{ color: 'var(--yellow)', fontSize: 24 }}>{stats.warning}</div>
            <div className="stat-label">Warning</div>
          </div>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-value" style={{ color: 'var(--text-muted)', fontSize: 24 }}>{stats.info}</div>
            <div className="stat-label">Info</div>
          </div>
        </div>
      )}

      {/* Live risk pulse */}
      <div className="card" style={{ padding: '12px 16px', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
          <span style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Live Risk Pulse
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            <span style={{ color: 'var(--red)', marginRight: 4 }}>&#9679;</span>blocks
            <span style={{ color: 'var(--accent)', margin: '0 4px 0 12px' }}>&#9644;</span>risk level
          </span>
        </div>
        <RiskPulse height={52} />
      </div>

      {/* System tabs + text filter */}
      {data && (
        <SystemTabs
          decisions={data.decisions}
          activeSystem={activeSystem}
          onSelect={setActiveSystem}
        />
      )}

      <div className="filters">
        <input
          placeholder="Filter by actor..."
          value={actor}
          onChange={e => setActor(e.target.value)}
          style={{ width: 220 }}
        />
        <select value={decisionFilter} onChange={e => setDecisionFilter(e.target.value)}>
          <option value="">All decisions</option>
          <option value="block">Block</option>
          <option value="require_review">Require Review</option>
          <option value="allow_with_logging">Allow with Logging</option>
          <option value="allow">Allow</option>
        </select>
      </div>

      {error && <div className="error">{error}</div>}

      {/* Decision cards — severity-sorted */}
      {loading && !data ? (
        <SkeletonCard count={5} />
      ) : (
        <div>
          {filteredDecisions.map(d => (
            <DecisionCard
              key={d.entry_id}
              entry={d}
              severity={classifySeverity(d)}
              isExpanded={expanded === d.entry_id}
              onToggle={() => setExpanded(expanded === d.entry_id ? null : d.entry_id)}
              onNavigateToActor={() => navigateToActor(d.actor_name)}
            />
          ))}
          {filteredDecisions.length === 0 && (
            <EmptyState />
          )}
        </div>
      )}
    </div>
  )
}
