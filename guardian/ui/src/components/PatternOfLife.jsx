/**
 * Pattern of Life — hour-of-day activity heatmap.
 *
 * Darktrace's signature concept: when does this actor normally operate?
 * A 24-column grid where each column is an hour. Color intensity = activity level.
 * Red cells indicate hours with blocked actions.
 */

export default function PatternOfLife({ pattern = [] }) {
  if (pattern.length === 0) {
    return (
      <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 16, textAlign: 'center' }}>
        No pattern data
      </div>
    )
  }

  const maxTotal = Math.max(...pattern.map(p => p.total), 1)

  return (
    <div>
      {/* Heatmap grid */}
      <div style={{ display: 'flex', gap: 2, alignItems: 'end', height: 48, marginBottom: 4 }}>
        {pattern.map(p => {
          const intensity = p.total / maxTotal
          const hasBlocks = p.block > 0
          const hasReviews = p.require_review > 0

          // Color: green for clean, yellow for reviews, red for blocks
          let color
          if (hasBlocks) {
            color = `rgba(248, 81, 73, ${0.3 + intensity * 0.7})`
          } else if (hasReviews) {
            color = `rgba(210, 153, 34, ${0.2 + intensity * 0.6})`
          } else if (p.total > 0) {
            color = `rgba(88, 166, 255, ${0.15 + intensity * 0.6})`
          } else {
            color = 'var(--border)'
          }

          return (
            <div
              key={p.hour}
              title={`${p.hour}:00 — ${p.total} actions (${p.block} blocks, ${p.require_review} reviews, ${p.allow} allows)`}
              style={{
                flex: 1,
                height: Math.max(4, intensity * 48),
                background: color,
                borderRadius: '2px 2px 0 0',
                transition: 'height 0.3s, background 0.3s',
                cursor: 'default',
                position: 'relative',
              }}
            >
              {/* Block indicator dot */}
              {hasBlocks && (
                <div style={{
                  position: 'absolute',
                  top: -4,
                  left: '50%',
                  transform: 'translateX(-50%)',
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  background: 'var(--red)',
                  boxShadow: '0 0 4px var(--red)',
                }} />
              )}
            </div>
          )
        })}
      </div>

      {/* Hour labels */}
      <div style={{ display: 'flex', gap: 2, fontSize: 9, color: 'var(--text-muted)' }}>
        {pattern.map(p => (
          <div key={p.hour} style={{ flex: 1, textAlign: 'center' }}>
            {p.hour % 6 === 0 ? `${p.hour}h` : ''}
          </div>
        ))}
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', gap: 16, marginTop: 8, fontSize: 11, color: 'var(--text-muted)' }}>
        <span><span style={{ color: 'var(--accent)' }}>&#9632;</span> normal</span>
        <span><span style={{ color: 'var(--yellow)' }}>&#9632;</span> reviews</span>
        <span><span style={{ color: 'var(--red)' }}>&#9632;</span> blocks</span>
        <span style={{ marginLeft: 'auto' }}>
          {pattern.reduce((s, p) => s + p.total, 0)} total actions
        </span>
      </div>
    </div>
  )
}
