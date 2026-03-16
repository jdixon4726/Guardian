import { useState } from 'react'
import { useApi, postApi } from '../hooks/useApi'

function DecisionBadge({ decision }) {
  return <span className={`badge badge-${decision}`}>{decision.replace('_', ' ')}</span>
}

function RiskBadge({ band }) {
  return <span className={`badge badge-${band}`}>{band}</span>
}

function ExpandedRow({ entry }) {
  const [feedbackSent, setFeedbackSent] = useState(false)
  const [feedbackType, setFeedbackType] = useState('')

  const sendFeedback = async (type) => {
    try {
      await postApi(`/v1/decisions/${entry.entry_id}/feedback`, {
        feedback_type: type,
        operator: 'dashboard-user',
        reason: '',
      })
      setFeedbackType(type)
      setFeedbackSent(true)
    } catch (e) {
      console.error('Feedback failed:', e)
    }
  }

  return (
    <tr>
      <td colSpan="6">
        <div className="expansion-panel">
          <div className="detail-grid">
            <div>
              <dt>Actor</dt>
              <dd>{entry.actor_name}</dd>
              <dt>Action</dt>
              <dd style={{ fontFamily: 'var(--mono)', fontSize: 13 }}>{entry.action}</dd>
              <dt>Target</dt>
              <dd>{entry.target_asset}</dd>
            </div>
            <div>
              <dt>Risk Score</dt>
              <dd>{entry.risk_score.toFixed(3)}</dd>
              <dt>Drift Score</dt>
              <dd>{entry.drift_score != null ? entry.drift_score.toFixed(3) : 'N/A'}</dd>
              <dt>Evaluated</dt>
              <dd>{new Date(entry.evaluated_at).toLocaleString()}</dd>
            </div>
          </div>
          <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
            {feedbackSent ? (
              <span style={{ color: 'var(--green)', fontSize: 13 }}>
                Feedback submitted: {feedbackType.replace('_', ' ')}
              </span>
            ) : (
              <>
                <button className="secondary" style={{ fontSize: 12, padding: '4px 10px' }}
                  onClick={() => sendFeedback('confirmed_correct')}>Correct</button>
                <button className="secondary" style={{ fontSize: 12, padding: '4px 10px', borderColor: 'var(--red)', color: 'var(--red)' }}
                  onClick={() => sendFeedback('false_positive')}>False Positive</button>
                <button className="secondary" style={{ fontSize: 12, padding: '4px 10px', borderColor: 'var(--orange)', color: 'var(--orange)' }}
                  onClick={() => sendFeedback('false_negative')}>False Negative</button>
              </>
            )}
          </div>
        </div>
      </td>
    </tr>
  )
}

export default function CommandCenter() {
  const [actor, setActor] = useState('')
  const [decisionFilter, setDecisionFilter] = useState('')
  const [expanded, setExpanded] = useState(null)

  const params = new URLSearchParams()
  params.set('limit', '100')
  if (actor) params.set('actor', actor)
  if (decisionFilter) params.set('decision', decisionFilter)

  const { data, loading, error } = useApi(
    `/v1/decisions/recent?${params.toString()}`,
    { autoRefresh: 15000 }
  )

  return (
    <div>
      <div className="page-header">
        <h1>Command Center</h1>
        <p>Real-time governance decision feed</p>
      </div>

      <div className="filters">
        <input
          placeholder="Filter by actor..."
          value={actor}
          onChange={e => setActor(e.target.value)}
          style={{ width: 200 }}
        />
        <select value={decisionFilter} onChange={e => setDecisionFilter(e.target.value)}>
          <option value="">All decisions</option>
          <option value="block">Block</option>
          <option value="require_review">Require Review</option>
          <option value="allow_with_logging">Allow with Logging</option>
          <option value="allow">Allow</option>
        </select>
        {data && <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>{data.total} decisions</span>}
      </div>

      {error && <div className="error">{error}</div>}

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        {loading && !data ? (
          <div className="loading">Loading decisions...</div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Decision</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Risk</th>
                <th>Drift</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {data?.decisions?.map(d => (
                <>
                  <tr key={d.entry_id} className="expandable-row"
                    onClick={() => setExpanded(expanded === d.entry_id ? null : d.entry_id)}>
                    <td><DecisionBadge decision={d.decision} /></td>
                    <td style={{ fontFamily: 'var(--mono)', fontSize: 13 }}>{d.actor_name}</td>
                    <td style={{ fontSize: 13 }}>{d.action}</td>
                    <td><RiskBadge band={d.risk_band} /></td>
                    <td style={{ fontFamily: 'var(--mono)', fontSize: 13 }}>
                      {d.drift_score != null ? d.drift_score.toFixed(2) : '-'}
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 13 }}>
                      {new Date(d.evaluated_at).toLocaleTimeString()}
                    </td>
                  </tr>
                  {expanded === d.entry_id && <ExpandedRow key={`exp-${d.entry_id}`} entry={d} />}
                </>
              ))}
              {data?.decisions?.length === 0 && (
                <tr><td colSpan="6" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>
                  No decisions found
                </td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
