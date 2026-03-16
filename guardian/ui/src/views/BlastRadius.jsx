import { useState } from 'react'
import { useApi } from '../hooks/useApi'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts'

function ScoreBar({ score }) {
  const color = score >= 0.7 ? 'var(--red)' : score >= 0.4 ? 'var(--orange)' : score >= 0.2 ? 'var(--yellow)' : 'var(--green)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ width: 100, height: 6, borderRadius: 3, background: 'var(--border)', overflow: 'hidden' }}>
        <div style={{ width: `${score * 100}%`, height: '100%', borderRadius: 3, background: color }} />
      </div>
      <span style={{ fontFamily: 'var(--mono)', fontSize: 13 }}>{(score * 100).toFixed(0)}%</span>
    </div>
  )
}

export default function BlastRadius() {
  const [actorName, setActorName] = useState('')
  const [searchName, setSearchName] = useState('')

  const { data: blastRadius, loading, error } = useApi(
    `/v1/graph/actor/${searchName}/blast-radius`,
    { enabled: !!searchName }
  )

  const { data: cascades } = useApi('/v1/graph/cascades?min_depth=2&limit=10')

  const handleSearch = (e) => {
    e.preventDefault()
    setSearchName(actorName)
  }

  const cascadeData = cascades?.cascades?.map(c => ({
    name: c.actors.map(a => a.replace('actor:', '')).join(' > '),
    risk: c.total_risk,
    depth: c.depth,
    crosses_trust: c.crosses_trust_boundary,
  })) || []

  return (
    <div>
      <div className="page-header">
        <h1>Blast Radius</h1>
        <p>Measure the operational impact of machine actors</p>
      </div>

      <form onSubmit={handleSearch} className="filters">
        <input
          placeholder="Enter actor name..."
          value={actorName}
          onChange={e => setActorName(e.target.value)}
          style={{ width: 300 }}
        />
        <button type="submit">Compute</button>
      </form>

      {error && <div className="error">{error}</div>}
      {loading && <div className="loading">Computing blast radius...</div>}

      {blastRadius && (
        <>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--accent)' }}>{blastRadius.direct_targets}</div>
              <div className="stat-label">Direct Targets</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--orange)' }}>{blastRadius.indirect_targets}</div>
              <div className="stat-label">Indirect Targets</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--red)' }}>{blastRadius.critical_targets}</div>
              <div className="stat-label">Critical Targets</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{blastRadius.systems_reached}</div>
              <div className="stat-label">Systems Reached</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{blastRadius.max_chain_depth}</div>
              <div className="stat-label">Max Chain Depth</div>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <span className="card-title">Blast Radius Score</span>
              <span className={`badge ${blastRadius.blast_radius_score >= 0.7 ? 'badge-critical' : blastRadius.blast_radius_score >= 0.4 ? 'badge-high' : 'badge-medium'}`}>
                {(blastRadius.blast_radius_score * 100).toFixed(0)}%
              </span>
            </div>
            <ScoreBar score={blastRadius.blast_radius_score} />
            <div style={{ marginTop: 12, fontSize: 13, color: 'var(--text-muted)' }}>
              This actor can directly affect {blastRadius.direct_targets} targets and indirectly
              reach {blastRadius.indirect_targets} more through automation cascades across {blastRadius.systems_reached} systems.
            </div>
          </div>

          {blastRadius.chains?.length > 0 && (
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Cascade Chains</div>
              {blastRadius.chains.map((chain, i) => (
                <div key={i} style={{
                  padding: '8px 12px',
                  background: 'var(--bg)',
                  borderRadius: 6,
                  marginBottom: 8,
                  fontFamily: 'var(--mono)',
                  fontSize: 13,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                }}>
                  {chain.map((eventId, j) => (
                    <span key={j}>
                      {j > 0 && <span style={{ color: 'var(--text-muted)', margin: '0 4px' }}>&rarr;</span>}
                      <span style={{ color: 'var(--accent)' }}>{eventId.slice(0, 8)}</span>
                    </span>
                  ))}
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {cascadeData.length > 0 && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 16 }}>Top Cascades by Risk</div>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={cascadeData} layout="vertical" margin={{ left: 180 }}>
              <CartesianGrid strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" domain={[0, 'auto']} />
              <YAxis dataKey="name" type="category" tick={{ fontSize: 11 }} width={170} />
              <Tooltip
                contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6 }}
                formatter={(val) => [val.toFixed(3), 'Total Risk']}
              />
              <Bar dataKey="risk" radius={[0, 4, 4, 0]}>
                {cascadeData.map((entry, i) => (
                  <Cell key={i} fill={entry.crosses_trust ? '#f85149' : '#58a6ff'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 8 }}>
            <span style={{ color: '#f85149' }}>Red</span> = crosses trust boundary |
            <span style={{ color: '#58a6ff' }}> Blue</span> = same trust domain
          </div>
        </div>
      )}

      {!blastRadius && !loading && !error && cascadeData.length === 0 && (
        <div className="card" style={{ textAlign: 'center', padding: 60, color: 'var(--text-muted)' }}>
          Enter an actor name to compute their blast radius, or wait for cascade data to populate.
        </div>
      )}
    </div>
  )
}
