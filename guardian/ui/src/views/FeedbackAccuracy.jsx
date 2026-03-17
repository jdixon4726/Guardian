import { useApi } from '../hooks/useApi'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'

const COLORS = {
  confirmed_correct: '#3fb950',
  false_positives: '#f85149',
  false_negatives: '#d29922',
  known_patterns: '#bc8cff',
}

export default function FeedbackAccuracy() {
  const { data: stats, loading, error } = useApi('/v1/feedback/stats', { autoRefresh: 30000 })
  const { data: adjustments } = useApi('/v1/feedback/prior-adjustments')

  const pieData = stats ? [
    { name: 'Correct', value: stats.confirmed_correct, color: COLORS.confirmed_correct },
    { name: 'False Positive', value: stats.false_positives, color: COLORS.false_positives },
    { name: 'False Negative', value: stats.false_negatives, color: COLORS.false_negatives },
    { name: 'Known Pattern', value: stats.known_patterns, color: COLORS.known_patterns },
  ].filter(d => d.value > 0) : []

  return (
    <div>
      <div className="page-header">
        <h1>Feedback & Accuracy</h1>
        <p>Track Guardian's decision accuracy and operator corrections</p>
      </div>

      {error && <div className="error">{error}</div>}
      {loading && <div className="loading">Loading feedback data...</div>}

      {stats && (
        <>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-value">{stats.total_feedback}</div>
              <div className="stat-label">Total Feedback</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--green)' }}>
                {(stats.accuracy_rate * 100).toFixed(1)}%
              </div>
              <div className="stat-label">Accuracy Rate</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--red)' }}>
                {(stats.false_positive_rate * 100).toFixed(1)}%
              </div>
              <div className="stat-label">False Positive Rate</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--green)' }}>{stats.confirmed_correct}</div>
              <div className="stat-label">Confirmed Correct</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--red)' }}>{stats.false_positives}</div>
              <div className="stat-label">False Positives</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--yellow)' }}>{stats.false_negatives}</div>
              <div className="stat-label">False Negatives</div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 16 }}>Feedback Distribution</div>
              {pieData.length > 0 ? (
                <ResponsiveContainer width="100%" height={280}>
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      dataKey="value"
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {pieData.map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6 }} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ textAlign: 'center', padding: 60, color: 'var(--text-muted)' }}>
                  No feedback submitted yet
                </div>
              )}
            </div>

            <div className="card">
              <div className="card-title" style={{ marginBottom: 16 }}>Bayesian Prior Adjustments</div>
              {adjustments?.adjustments?.length > 0 ? (
                <table className="table">
                  <thead>
                    <tr>
                      <th>Actor Type</th>
                      <th>Alpha Adj</th>
                      <th>Beta Adj</th>
                      <th>Effect</th>
                    </tr>
                  </thead>
                  <tbody>
                    {adjustments.adjustments.map((a, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'var(--mono)', fontSize: 13 }}>{a.actor_type}</td>
                        <td style={{ color: a.alpha_adjustment > 0 ? 'var(--red)' : 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                          {a.alpha_adjustment > 0 ? `+${a.alpha_adjustment.toFixed(1)}` : '0'}
                        </td>
                        <td style={{ color: a.beta_adjustment > 0 ? 'var(--green)' : 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                          {a.beta_adjustment > 0 ? `+${a.beta_adjustment.toFixed(1)}` : '0'}
                        </td>
                        <td style={{ fontSize: 13 }}>{a.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)', fontSize: 13 }}>
                  No prior adjustments yet. Feedback on decisions tunes the Bayesian model
                  automatically.
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {!stats && !loading && !error && (
        <div className="card" style={{ textAlign: 'center', padding: 60, color: 'var(--text-muted)' }}>
          Submit feedback on decisions in the Command Center to see accuracy metrics here.
        </div>
      )}
    </div>
  )
}
