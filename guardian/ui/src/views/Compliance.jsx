import { useState } from 'react'
import { useApi } from '../hooks/useApi'

function ScoreBar({ label, satisfied, total }) {
  const pct = total > 0 ? (satisfied / total * 100) : 0
  const color = pct >= 90 ? 'var(--green)' : pct >= 70 ? 'var(--yellow)' : 'var(--red)'
  return (
    <div className="card" style={{ padding: 16, marginBottom: 8 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
        <span style={{ fontSize: 14, fontWeight: 600 }}>{label}</span>
        <span style={{ fontFamily: 'var(--mono)', color, fontWeight: 700 }}>{pct.toFixed(0)}%</span>
      </div>
      <div style={{ height: 6, borderRadius: 3, background: 'var(--border)', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 3, transition: 'width 0.5s var(--ease-default)' }} />
      </div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
        {satisfied}/{total} controls satisfied
      </div>
    </div>
  )
}

export default function Compliance() {
  const [window, setWindow] = useState(720)
  const { data: report, loading, refetch } = useApi(`/v1/compliance/report?window_hours=${window}`)
  const { data: frameworks } = useApi('/v1/compliance/frameworks')

  return (
    <div>
      <div className="page-header">
        <h1>Compliance</h1>
        <p>Regulatory control mapping and audit evidence for NIST 800-53, HIPAA, FedRAMP, and EU AI Act</p>
      </div>

      <div style={{ display: 'flex', gap: 12, marginBottom: 20, alignItems: 'center' }}>
        <select value={window} onChange={e => setWindow(Number(e.target.value))} style={{ fontSize: 13 }}>
          <option value={24}>Last 24 hours</option>
          <option value={168}>Last 7 days</option>
          <option value={720}>Last 30 days</option>
          <option value={2160}>Last 90 days</option>
        </select>
        <button onClick={refetch} className="secondary" style={{ fontSize: 12 }}>Refresh</button>
        {report && (
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {report.audit_entries_analyzed} entries analyzed |
            Hash chain: <span style={{ color: report.hash_chain_valid ? 'var(--green)' : 'var(--red)', fontWeight: 600 }}>
              {report.hash_chain_valid ? 'VALID' : 'BROKEN'}
            </span>
          </span>
        )}
      </div>

      {/* Framework Scores */}
      {report?.framework_scores && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 8, marginBottom: 24 }}>
          {Object.entries(report.framework_scores).map(([fw, score]) => (
            <ScoreBar key={fw} label={fw} satisfied={score.satisfied} total={score.total} />
          ))}
        </div>
      )}

      {/* Summary Stats */}
      {report?.statistics && (
        <div style={{ display: 'flex', gap: 12, marginBottom: 24 }}>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-value" style={{ fontSize: 24 }}>{report.statistics.total_evaluations}</div>
            <div className="stat-label">Evaluations</div>
          </div>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-value" style={{ fontSize: 24, color: 'var(--accent)' }}>{report.statistics.unique_actors}</div>
            <div className="stat-label">Actors</div>
          </div>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-value" style={{ fontSize: 24, color: 'var(--red)' }}>{report.statistics.high_risk_count}</div>
            <div className="stat-label">High Risk</div>
          </div>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-value" style={{ fontSize: 24, color: 'var(--orange)' }}>{report.statistics.privileged_actions}</div>
            <div className="stat-label">Privileged</div>
          </div>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-value" style={{ fontSize: 24, color: 'var(--yellow)' }}>{report.statistics.drift_alerts}</div>
            <div className="stat-label">Drift Alerts</div>
          </div>
        </div>
      )}

      {/* Control Details */}
      {report?.controls && (
        <div>
          <h3 style={{ fontSize: 16, marginBottom: 12 }}>Control Mapping</h3>
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <th style={{ padding: '10px 12px', textAlign: 'left', color: 'var(--text-muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Control</th>
                  <th style={{ padding: '10px 12px', textAlign: 'left', color: 'var(--text-muted)', fontSize: 11, textTransform: 'uppercase' }}>Framework</th>
                  <th style={{ padding: '10px 12px', textAlign: 'left', color: 'var(--text-muted)', fontSize: 11, textTransform: 'uppercase' }}>Status</th>
                  <th style={{ padding: '10px 12px', textAlign: 'left', color: 'var(--text-muted)', fontSize: 11, textTransform: 'uppercase' }}>Evidence</th>
                </tr>
              </thead>
              <tbody>
                {report.controls.map((c, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '8px 12px' }}>
                      <div style={{ fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--accent)' }}>{c.control_id}</div>
                      <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>{c.control_name}</div>
                    </td>
                    <td style={{ padding: '8px 12px' }}>
                      <span style={{ fontSize: 11, padding: '2px 6px', borderRadius: 4, background: 'var(--surface-hover)', color: 'var(--text-muted)' }}>
                        {c.framework}
                      </span>
                    </td>
                    <td style={{ padding: '8px 12px' }}>
                      <span style={{
                        fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 4,
                        background: c.status === 'satisfied' ? 'rgba(48,209,88,0.15)' : c.status === 'no_data' ? 'rgba(255,214,10,0.15)' : 'rgba(255,69,58,0.15)',
                        color: c.status === 'satisfied' ? 'var(--green)' : c.status === 'no_data' ? 'var(--yellow)' : 'var(--red)',
                      }}>
                        {c.status}
                      </span>
                    </td>
                    <td style={{ padding: '8px 12px', color: 'var(--text-muted)', fontSize: 11, maxWidth: 300 }}>
                      {c.evidence_summary}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {loading && !report && (
        <div className="card" style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
          Generating compliance report...
        </div>
      )}
    </div>
  )
}
