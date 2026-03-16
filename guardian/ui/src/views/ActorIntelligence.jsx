import { useState } from 'react'
import { useApi } from '../hooks/useApi'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'

function TrustBar({ level }) {
  const color = level >= 0.7 ? 'var(--green)' : level >= 0.4 ? 'var(--yellow)' : 'var(--red)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
      <div className="trust-bar">
        <div className="trust-bar-fill" style={{ width: `${level * 100}%`, background: color }} />
      </div>
      <span style={{ fontFamily: 'var(--mono)', fontSize: 14 }}>{(level * 100).toFixed(0)}%</span>
    </div>
  )
}

export default function ActorIntelligence() {
  const [actorName, setActorName] = useState('')
  const [searchName, setSearchName] = useState('')

  const { data: profile, loading, error } = useApi(
    `/v1/actors/${searchName}/profile`,
    { enabled: !!searchName }
  )

  const { data: targets } = useApi(
    `/v1/graph/actor/${searchName}/targets`,
    { enabled: !!searchName }
  )

  const { data: scopeDrift } = useApi(
    `/v1/graph/actor/${searchName}/scope-drift`,
    { enabled: !!searchName }
  )

  const handleSearch = (e) => {
    e.preventDefault()
    setSearchName(actorName)
  }

  const topActionsData = profile?.top_actions
    ? Object.entries(profile.top_actions).map(([name, count]) => ({ name, count }))
    : []

  return (
    <div>
      <div className="page-header">
        <h1>Actor Intelligence</h1>
        <p>Behavioral profile, trust trajectory, and drift analysis</p>
      </div>

      <form onSubmit={handleSearch} className="filters">
        <input
          placeholder="Enter actor name..."
          value={actorName}
          onChange={e => setActorName(e.target.value)}
          style={{ width: 300 }}
        />
        <button type="submit">Analyze</button>
      </form>

      {error && <div className="error">{error}</div>}

      {loading && <div className="loading">Loading profile...</div>}

      {profile && (
        <>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-value">{profile.total_actions}</div>
              <div className="stat-label">Total Actions</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--green)' }}>{profile.total_allows}</div>
              <div className="stat-label">Allows</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--yellow)' }}>{profile.total_reviews}</div>
              <div className="stat-label">Reviews</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--red)' }}>{profile.total_blocks}</div>
              <div className="stat-label">Blocks</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{profile.actions_last_hour}</div>
              <div className="stat-label">Last Hour</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{profile.actions_last_day}</div>
              <div className="stat-label">Last 24h</div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div className="card">
              <div className="card-header">
                <span className="card-title">Trust Level</span>
                <span className={`badge badge-${profile.trust_band === 'high' ? 'allow' : profile.trust_band === 'neutral' ? 'require_review' : 'block'}`}>
                  {profile.trust_band}
                </span>
              </div>
              <TrustBar level={profile.trust_level} />
              <div style={{ marginTop: 12, fontSize: 13, color: 'var(--text-muted)' }}>
                History: {profile.history_days} days
                {profile.first_seen && <> | First seen: {new Date(profile.first_seen).toLocaleDateString()}</>}
              </div>
            </div>

            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Scope Drift</div>
              {scopeDrift ? (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                    <span style={{ fontSize: 13 }}>Drift Score</span>
                    <span style={{
                      fontFamily: 'var(--mono)',
                      color: scopeDrift.is_drifting ? 'var(--red)' : 'var(--green)'
                    }}>
                      {scopeDrift.scope_drift_score.toFixed(3)}
                    </span>
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                    {scopeDrift.new_targets?.length || 0} new targets |
                    {' '}{scopeDrift.new_systems?.length || 0} new systems
                  </div>
                  {scopeDrift.is_drifting && (
                    <div style={{ marginTop: 8, color: 'var(--orange)', fontSize: 13 }}>
                      Actor is expanding into new territory
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No drift data</div>
              )}
            </div>
          </div>

          {topActionsData.length > 0 && (
            <div className="card">
              <div className="card-title" style={{ marginBottom: 16 }}>Top Actions</div>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={topActionsData} layout="vertical" margin={{ left: 120 }}>
                  <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                  <XAxis type="number" />
                  <YAxis dataKey="name" type="category" tick={{ fontSize: 12 }} width={110} />
                  <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6 }} />
                  <Bar dataKey="count" fill="var(--accent)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {targets?.targets?.length > 0 && (
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Targets Affected</div>
              <table className="table">
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>System</th>
                    <th>Frequency</th>
                    <th>Avg Risk</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {targets.targets.slice(0, 20).map(t => (
                    <tr key={t.target_id}>
                      <td style={{ fontFamily: 'var(--mono)', fontSize: 13 }}>{t.target_name}</td>
                      <td>{t.target_system}</td>
                      <td>{t.frequency}</td>
                      <td style={{ fontFamily: 'var(--mono)' }}>{t.avg_risk?.toFixed(3) || '-'}</td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 13 }}>
                        {t.last_seen ? new Date(t.last_seen).toLocaleDateString() : '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {!profile && !loading && !error && (
        <div className="card" style={{ textAlign: 'center', padding: 60, color: 'var(--text-muted)' }}>
          Enter an actor name to view their behavioral profile
        </div>
      )}
    </div>
  )
}
