import { useState } from 'react'
import { useApi } from '../hooks/useApi'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'

export default function Reconciliation() {
  const [windowMinutes, setWindowMinutes] = useState(60)

  const { data, loading, error, refetch } = useApi(
    `/v1/reconciliation/report?window_minutes=${windowMinutes}`,
    { autoRefresh: 60000 }
  )

  const coverageRate = data && data.total_external_actions > 0
    ? data.total_governed / data.total_external_actions
    : 1.0

  const pieData = data ? [
    { name: 'Governed', value: data.total_governed, color: '#3fb950' },
    { name: 'Ungoverned', value: data.total_ungoverned, color: '#f85149' },
  ].filter(d => d.value > 0) : []

  return (
    <div>
      <div className="page-header">
        <h1>Reconciliation</h1>
        <p>Detect infrastructure actions that bypassed Guardian governance</p>
      </div>

      <div className="filters">
        <label style={{ fontSize: 13, color: 'var(--text-muted)' }}>Time window:</label>
        <select value={windowMinutes} onChange={e => setWindowMinutes(Number(e.target.value))}>
          <option value={15}>15 minutes</option>
          <option value={60}>1 hour</option>
          <option value={240}>4 hours</option>
          <option value={480}>8 hours</option>
          <option value={1440}>24 hours</option>
        </select>
        <button className="secondary" onClick={refetch}>Refresh</button>
      </div>

      {error && <div className="error">{error}</div>}
      {loading && !data && <div className="loading">Running reconciliation...</div>}

      {data && (
        <>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-value">{data.total_external_actions}</div>
              <div className="stat-label">Total Actions</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--green)' }}>{data.total_governed}</div>
              <div className="stat-label">Governed</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--red)' }}>{data.total_ungoverned}</div>
              <div className="stat-label">Ungoverned</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: coverageRate >= 0.9 ? 'var(--green)' : coverageRate >= 0.7 ? 'var(--yellow)' : 'var(--red)' }}>
                {(coverageRate * 100).toFixed(1)}%
              </div>
              <div className="stat-label">Coverage</div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 16 }}>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 16 }}>Coverage</div>
              {pieData.length > 0 ? (
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={80}
                      dataKey="value"
                    >
                      {pieData.map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6 }} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
                  No external actions in window
                </div>
              )}
              <div style={{ textAlign: 'center', fontSize: 13, color: 'var(--text-muted)' }}>
                {data.window_start && (
                  <>
                    {new Date(data.window_start).toLocaleTimeString()} - {new Date(data.window_end).toLocaleTimeString()}
                  </>
                )}
              </div>
            </div>

            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Ungoverned Actions</div>
              {data.ungoverned_actions?.length > 0 ? (
                <table className="table">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Actor</th>
                      <th>Action</th>
                      <th>Resource</th>
                      <th>Explanation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.ungoverned_actions.map((a, i) => (
                      <tr key={i}>
                        <td>
                          <span className={`badge ${a.severity === 'critical' ? 'badge-critical' : a.severity === 'high' ? 'badge-high' : 'badge-medium'}`}>
                            {a.severity}
                          </span>
                        </td>
                        <td style={{ fontFamily: 'var(--mono)', fontSize: 13 }}>{a.actor}</td>
                        <td style={{ fontSize: 13 }}>{a.action}</td>
                        <td style={{ fontFamily: 'var(--mono)', fontSize: 13 }}>{a.resource}</td>
                        <td style={{ fontSize: 13, color: 'var(--text-muted)' }}>{a.explanation}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div style={{ textAlign: 'center', padding: 40, color: 'var(--green)' }}>
                  All actions within this window were governed
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
