import { useState, useMemo, useEffect, useRef } from 'react'
import { useApi } from '../hooks/useApi'
import DecisionCard from '../components/DecisionCard'
import RiskGauge from '../components/RiskGauge'
import RiskPulse from '../components/RiskPulse'

export default function CommandCenter() {
  const [actor, setActor] = useState('')
  const [decisionFilter, setDecisionFilter] = useState('')
  const [expanded, setExpanded] = useState(null)

  const params = new URLSearchParams()
  params.set('limit', '200')
  if (actor) params.set('actor', actor)
  if (decisionFilter) params.set('decision', decisionFilter)

  const { data, loading, error } = useApi(
    `/v1/decisions/recent?${params.toString()}`,
    { autoRefresh: 15000 }
  )

  // Compute summary stats
  const stats = useMemo(() => {
    if (!data?.decisions) return null
    const decisions = data.decisions
    const blocks = decisions.filter(d => d.decision === 'block').length
    const reviews = decisions.filter(d => d.decision === 'require_review').length
    const allows = decisions.filter(d => d.decision === 'allow' || d.decision === 'allow_with_logging').length
    const avgRisk = decisions.length > 0
      ? decisions.reduce((sum, d) => sum + d.risk_score, 0) / decisions.length
      : 0
    const highRisk = decisions.filter(d => d.risk_score >= 0.6).length
    return { blocks, reviews, allows, avgRisk, highRisk, total: decisions.length }
  }, [data])

  return (
    <div>
      <div className="page-header">
        <h1>Command Center</h1>
        <p>Real-time governance decision feed</p>
      </div>

      {/* Summary cards — Darktrace-inspired overview strip */}
      {stats && (
        <div style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
          <div className="stat-card" style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 12 }}>
            <RiskGauge score={stats.avgRisk} size={52} strokeWidth={5} />
            <div>
              <div className="stat-label">Avg Risk</div>
              <div style={{ fontSize: 13 }}>{stats.total} decisions</div>
            </div>
          </div>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-value" style={{ color: 'var(--red)', fontSize: 24 }}>{stats.blocks}</div>
            <div className="stat-label">Blocked</div>
          </div>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-value" style={{ color: 'var(--yellow)', fontSize: 24 }}>{stats.reviews}</div>
            <div className="stat-label">Review</div>
          </div>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-value" style={{ color: 'var(--green)', fontSize: 24 }}>{stats.allows}</div>
            <div className="stat-label">Allowed</div>
          </div>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-value" style={{ color: 'var(--orange)', fontSize: 24 }}>{stats.highRisk}</div>
            <div className="stat-label">High Risk</div>
          </div>
        </div>
      )}

      {/* Live risk pulse — infrastructure heart rate */}
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

      {/* Filters */}
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

      {loading && !data ? (
        <div className="loading">Loading decisions...</div>
      ) : (
        <div>
          {data?.decisions?.map(d => (
            <DecisionCard
              key={d.entry_id}
              entry={d}
              isExpanded={expanded === d.entry_id}
              onToggle={() => setExpanded(expanded === d.entry_id ? null : d.entry_id)}
            />
          ))}
          {data?.decisions?.length === 0 && (
            <div className="card" style={{ textAlign: 'center', padding: 60, color: 'var(--text-muted)' }}>
              No decisions found. Submit evaluations through the API to see them here.
            </div>
          )}
        </div>
      )}
    </div>
  )
}
