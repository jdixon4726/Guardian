/**
 * Cascade Context — shows which automation chains an actor participates in.
 *
 * Visualizes upstream triggers (who causes this actor to act)
 * and downstream effects (what this actor's actions trigger).
 */
import { useApi } from '../hooks/useApi'

export default function CascadeContext({ actorName }) {
  const { data: cascades } = useApi('/v1/graph/cascades?min_depth=2&limit=50')
  const { data: pathDrift } = useApi(
    `/v1/graph/actor/${actorName}/path-drift`,
    { enabled: !!actorName }
  )

  if (!cascades?.cascades) return null

  // Find cascades involving this actor
  const actorId = `actor:${actorName}`
  const relevant = cascades.cascades.filter(c => c.actors.includes(actorId))

  if (relevant.length === 0) {
    return (
      <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 16, textAlign: 'center' }}>
        No automation chains detected for this actor
      </div>
    )
  }

  // Determine upstream and downstream actors
  const upstream = new Set()
  const downstream = new Set()

  relevant.forEach(cascade => {
    const idx = cascade.actors.indexOf(actorId)
    if (idx > 0) {
      cascade.actors.slice(0, idx).forEach(a => upstream.add(a.replace('actor:', '')))
    }
    if (idx < cascade.actors.length - 1) {
      cascade.actors.slice(idx + 1).forEach(a => downstream.add(a.replace('actor:', '')))
    }
  })

  return (
    <div>
      {/* Chain visualization */}
      {relevant.slice(0, 5).map((cascade, i) => (
        <div key={i} style={{
          display: 'flex',
          alignItems: 'center',
          gap: 0,
          padding: '8px 0',
          borderBottom: i < relevant.length - 1 ? '1px solid var(--border)' : 'none',
        }}>
          {cascade.actors.map((actor, j) => {
            const name = actor.replace('actor:', '')
            const isThis = actor === actorId
            return (
              <div key={j} style={{ display: 'flex', alignItems: 'center' }}>
                {j > 0 && (
                  <div style={{
                    width: 24,
                    height: 2,
                    background: 'var(--border)',
                    position: 'relative',
                  }}>
                    <div style={{
                      position: 'absolute',
                      right: -3,
                      top: -3,
                      width: 0,
                      height: 0,
                      borderLeft: '6px solid var(--border)',
                      borderTop: '4px solid transparent',
                      borderBottom: '4px solid transparent',
                    }} />
                  </div>
                )}
                <div style={{
                  padding: '4px 10px',
                  borderRadius: 16,
                  fontSize: 12,
                  fontFamily: 'var(--mono)',
                  background: isThis ? 'rgba(88, 166, 255, 0.2)' : 'var(--bg)',
                  border: `1px solid ${isThis ? 'var(--accent)' : 'var(--border)'}`,
                  color: isThis ? 'var(--accent)' : 'var(--text-muted)',
                  fontWeight: isThis ? 600 : 400,
                  whiteSpace: 'nowrap',
                }}>
                  {name}
                </div>
              </div>
            )
          })}
          <div style={{ marginLeft: 12, fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
            risk {cascade.total_risk.toFixed(2)}
            {cascade.crosses_trust_boundary && (
              <span style={{ color: 'var(--orange)', marginLeft: 6 }}>crosses trust boundary</span>
            )}
          </div>
        </div>
      ))}

      {/* Summary */}
      <div style={{ display: 'flex', gap: 24, marginTop: 12, fontSize: 12 }}>
        {upstream.size > 0 && (
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Triggered by: </span>
            {[...upstream].map((a, i) => (
              <span key={a}>
                {i > 0 && ', '}
                <span style={{ color: 'var(--accent)', fontFamily: 'var(--mono)' }}>{a}</span>
              </span>
            ))}
          </div>
        )}
        {downstream.size > 0 && (
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Triggers: </span>
            {[...downstream].map((a, i) => (
              <span key={a}>
                {i > 0 && ', '}
                <span style={{ color: 'var(--orange)', fontFamily: 'var(--mono)' }}>{a}</span>
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Path drift warning */}
      {pathDrift?.is_drifting && (
        <div style={{
          marginTop: 12,
          padding: '8px 12px',
          background: 'rgba(219, 109, 40, 0.1)',
          border: '1px solid var(--orange)',
          borderRadius: 6,
          fontSize: 12,
          color: 'var(--orange)',
        }}>
          New automation chain detected — this actor is participating in paths
          not seen in its historical baseline.
        </div>
      )}
    </div>
  )
}
