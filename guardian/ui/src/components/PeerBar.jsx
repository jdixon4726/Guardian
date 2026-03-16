/**
 * Peer comparison bar — shows an actor's score relative to peer group.
 * Darktrace-inspired: gray range = peer group norm, colored dot = this actor.
 * If dot is outside the range, it's visually alarming.
 */
export default function PeerBar({ value, peerMin = 0.3, peerMax = 0.8, label = '' }) {
  const color = value >= 0.7 ? 'var(--green)'
    : value >= 0.4 ? 'var(--yellow)'
    : 'var(--red)'

  const isOutlier = value < peerMin || value > peerMax

  return (
    <div>
      {label && (
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{label}</span>
          <span style={{ fontSize: 12, fontFamily: 'var(--mono)', color }}>
            {(value * 100).toFixed(0)}%
            {isOutlier && <span style={{ color: 'var(--orange)', marginLeft: 4 }}>(outlier)</span>}
          </span>
        </div>
      )}
      <div className="peer-bar">
        <div
          className="peer-range"
          style={{
            left: `${peerMin * 100}%`,
            width: `${(peerMax - peerMin) * 100}%`,
          }}
        />
        <div
          className="peer-marker"
          style={{
            left: `${value * 100}%`,
            background: color,
            boxShadow: isOutlier ? `0 0 8px ${color}` : 'none',
          }}
        />
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
        <span>0</span>
        <span style={{ opacity: 0.6 }}>peer range: {(peerMin * 100).toFixed(0)}-{(peerMax * 100).toFixed(0)}%</span>
        <span>100</span>
      </div>
    </div>
  )
}
