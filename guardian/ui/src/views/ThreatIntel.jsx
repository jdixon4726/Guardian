import { useState } from 'react'
import { useApi, postApi } from '../hooks/useApi'

function StatusBadge({ status }) {
  const colors = {
    active: 'var(--green)',
    pending: 'var(--yellow)',
    expired: 'var(--text-muted)',
    rejected: 'var(--red)',
    superseded: 'var(--text-muted)',
  }
  return (
    <span
      className={`badge badge-${status}`}
      style={{
        background: `${colors[status] || 'var(--text-muted)'}22`,
        color: colors[status] || 'var(--text-muted)',
        padding: '2px 8px',
        borderRadius: 4,
        fontSize: 11,
        fontWeight: 600,
        textTransform: 'uppercase',
      }}
    >
      {status}
    </span>
  )
}

export default function ThreatIntel() {
  const [syncing, setSyncing] = useState(false)
  const [syncResult, setSyncResult] = useState(null)
  const [statusFilter, setStatusFilter] = useState('')

  const overlayUrl = statusFilter
    ? `/v1/threat-intel/overlays?status=${statusFilter}`
    : '/v1/threat-intel/overlays'
  const { data: overlays, loading, refetch } = useApi(overlayUrl, { autoRefresh: 30000 })
  const { data: audit } = useApi('/v1/threat-intel/audit', { autoRefresh: 60000 })

  const syncFeeds = async () => {
    setSyncing(true)
    setSyncResult(null)
    try {
      const res = await postApi('/v1/threat-intel/sync', {})
      setSyncResult(res)
      refetch()
    } catch (err) {
      setSyncResult({ success: false, errors: [err.message] })
    } finally {
      setSyncing(false)
    }
  }

  const activateOverlay = async (id) => {
    try {
      await postApi(`/v1/threat-intel/overlays/${id}/activate`, {})
      refetch()
    } catch (err) {
      alert(`Activation failed: ${err.message}`)
    }
  }

  const rejectOverlay = async (id) => {
    const reason = prompt('Rejection reason:')
    if (!reason) return
    try {
      await postApi(`/v1/threat-intel/overlays/${id}/reject?reason=${encodeURIComponent(reason)}`, {})
      refetch()
    } catch (err) {
      alert(`Rejection failed: ${err.message}`)
    }
  }

  const overlayList = Array.isArray(overlays) ? overlays : []
  const auditList = Array.isArray(audit) ? audit : []

  const activeCount = overlayList.filter(o => o.status === 'active').length
  const pendingCount = overlayList.filter(o => o.status === 'pending').length

  return (
    <div>
      <div className="page-header">
        <h1>Threat Intelligence</h1>
        <p>Risk overlays from authoritative feeds (CISA KEV, MITRE ATT&CK)</p>
      </div>

      {/* Sync Controls */}
      <div className="card" style={{ padding: 16, marginBottom: 16, display: 'flex', alignItems: 'center', gap: 16 }}>
        <button
          onClick={syncFeeds}
          disabled={syncing}
          style={{
            background: 'var(--accent)',
            color: '#fff',
            border: 'none',
            borderRadius: 6,
            padding: '8px 20px',
            fontSize: 13,
            fontWeight: 600,
            cursor: syncing ? 'wait' : 'pointer',
            opacity: syncing ? 0.6 : 1,
          }}
        >
          {syncing ? 'Syncing CISA KEV...' : 'Sync Threat Feeds'}
        </button>

        <div style={{ display: 'flex', gap: 16 }}>
          <div>
            <span style={{ fontSize: 20, fontWeight: 700, color: 'var(--green)' }}>{activeCount}</span>
            <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 4 }}>active overlays</span>
          </div>
          <div>
            <span style={{ fontSize: 20, fontWeight: 700, color: 'var(--yellow)' }}>{pendingCount}</span>
            <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 4 }}>pending review</span>
          </div>
        </div>

        {syncResult && (
          <div style={{ fontSize: 12, color: syncResult.success ? 'var(--green)' : 'var(--red)' }}>
            {syncResult.success
              ? `Synced: ${syncResult.entries_processed} entries, ${syncResult.overlays_created} new overlays`
              : `Error: ${syncResult.errors?.join(', ')}`}
          </div>
        )}
      </div>

      {/* Anti-Poisoning Notice */}
      <div className="card" style={{ padding: '12px 16px', marginBottom: 16, borderLeft: '3px solid var(--accent)', fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>
        <strong style={{ color: 'var(--text)' }}>Anti-Poisoning Protection:</strong>{' '}
        Overlays can only increase risk (never decrease). Max single overlay: +0.20. Combined cap: +0.30.
        Pending overlays do not affect scoring until explicitly approved.
        Sources: CISA (.gov), MITRE (.org), NVD (.gov) only.
      </div>

      {/* Status Filter */}
      <div className="filters" style={{ marginBottom: 16 }}>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="pending">Pending Review</option>
          <option value="expired">Expired</option>
          <option value="rejected">Rejected</option>
        </select>
      </div>

      {/* Overlay List */}
      {loading && !overlays ? (
        <div className="card" style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Loading overlays...</div>
      ) : overlayList.length === 0 ? (
        <div className="card" style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
          No overlays yet. Click "Sync Threat Feeds" to fetch the latest CISA KEV catalog.
        </div>
      ) : (
        <div>
          {overlayList.map(o => (
            <div key={o.overlay_id} className="card decision-card" style={{ marginBottom: 8, padding: '12px 16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <StatusBadge status={o.status} />
                    <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>{o.title}</span>
                  </div>
                  {o.description && (
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4, maxWidth: 600 }}>
                      {o.description.slice(0, 200)}{o.description.length > 200 ? '...' : ''}
                    </div>
                  )}
                  <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--text-muted)' }}>
                    <span>Risk: <strong style={{ color: 'var(--orange)' }}>+{o.risk_adjustment?.toFixed(2)}</strong></span>
                    <span>Source: {o.source}</span>
                    {o.cve_ids && JSON.parse(o.cve_ids || '[]').length > 0 && (
                      <span>CVEs: {JSON.parse(o.cve_ids).join(', ')}</span>
                    )}
                    <span>Expires: {o.expires_at?.split('T')[0]}</span>
                  </div>
                </div>
                {o.status === 'pending' && (
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button
                      onClick={() => activateOverlay(o.overlay_id)}
                      style={{ background: 'var(--green)', color: '#fff', border: 'none', borderRadius: 4, padding: '4px 12px', fontSize: 11, fontWeight: 600, cursor: 'pointer' }}
                    >
                      Approve
                    </button>
                    <button
                      onClick={() => rejectOverlay(o.overlay_id)}
                      style={{ background: 'var(--red)', color: '#fff', border: 'none', borderRadius: 4, padding: '4px 12px', fontSize: 11, fontWeight: 600, cursor: 'pointer' }}
                    >
                      Reject
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Audit Trail */}
      {auditList.length > 0 && (
        <div style={{ marginTop: 24 }}>
          <h3 style={{ fontSize: 14, marginBottom: 8, color: 'var(--text-muted)' }}>Overlay Audit Trail</h3>
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <th style={{ padding: '8px 12px', textAlign: 'left', color: 'var(--text-muted)' }}>Time</th>
                  <th style={{ padding: '8px 12px', textAlign: 'left', color: 'var(--text-muted)' }}>Action</th>
                  <th style={{ padding: '8px 12px', textAlign: 'left', color: 'var(--text-muted)' }}>Overlay</th>
                  <th style={{ padding: '8px 12px', textAlign: 'left', color: 'var(--text-muted)' }}>Details</th>
                </tr>
              </thead>
              <tbody>
                {auditList.slice(0, 20).map((a, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '6px 12px', color: 'var(--text-muted)', fontVariantNumeric: 'tabular-nums' }}>
                      {a.timestamp?.split('T')[1]?.split('.')[0] || a.timestamp}
                    </td>
                    <td style={{ padding: '6px 12px' }}>
                      <span style={{
                        color: a.action === 'activated' ? 'var(--green)'
                          : a.action === 'rejected' ? 'var(--red)'
                          : a.action === 'created' ? 'var(--accent)'
                          : 'var(--text-muted)',
                        fontWeight: 600,
                      }}>{a.action}</span>
                    </td>
                    <td style={{ padding: '6px 12px', fontFamily: 'monospace', fontSize: 11 }}>{a.overlay_id?.slice(0, 8)}</td>
                    <td style={{ padding: '6px 12px', color: 'var(--text-muted)' }}>{a.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
