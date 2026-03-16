/**
 * Activity Timeline — horizontal timeline of an actor's recent decisions.
 *
 * Each event is a colored dot on a timeline track.
 * Green = allow, Blue = allow_with_logging, Yellow = review, Red = block.
 * Hover for detail tooltip. Recent events on the right.
 */
import { useState } from 'react'

const DECISION_COLORS = {
  allow: 'var(--green)',
  allow_with_logging: 'var(--accent)',
  require_review: 'var(--yellow)',
  block: 'var(--red)',
}

export default function ActivityTimeline({ events = [] }) {
  const [hoveredIdx, setHoveredIdx] = useState(null)

  if (events.length === 0) {
    return (
      <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 16, textAlign: 'center' }}>
        No activity recorded
      </div>
    )
  }

  // Reverse so oldest is left, newest is right
  const ordered = [...events].reverse()
  const maxRisk = Math.max(...ordered.map(e => e.risk_score), 0.5)

  return (
    <div style={{ position: 'relative' }}>
      {/* Timeline track */}
      <div style={{
        display: 'flex',
        alignItems: 'end',
        gap: 2,
        height: 64,
        padding: '0 4px',
        borderBottom: '1px solid var(--border)',
      }}>
        {ordered.map((event, i) => {
          const color = DECISION_COLORS[event.decision] || 'var(--text-muted)'
          const height = Math.max(8, (event.risk_score / maxRisk) * 48)
          const isHovered = hoveredIdx === i

          return (
            <div
              key={i}
              onMouseEnter={() => setHoveredIdx(i)}
              onMouseLeave={() => setHoveredIdx(null)}
              style={{
                flex: 1,
                maxWidth: 12,
                minWidth: 3,
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'end',
                alignItems: 'center',
                cursor: 'pointer',
                position: 'relative',
              }}
            >
              <div style={{
                width: '100%',
                height,
                borderRadius: '2px 2px 0 0',
                background: color,
                opacity: isHovered ? 1 : 0.7,
                transition: 'opacity 0.15s, height 0.3s',
                boxShadow: isHovered ? `0 0 8px ${color}` : 'none',
              }} />
            </div>
          )
        })}
      </div>

      {/* Tooltip */}
      {hoveredIdx !== null && ordered[hoveredIdx] && (
        <div style={{
          position: 'absolute',
          top: -60,
          left: `${(hoveredIdx / ordered.length) * 100}%`,
          transform: 'translateX(-50%)',
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 6,
          padding: '6px 10px',
          fontSize: 12,
          zIndex: 10,
          whiteSpace: 'nowrap',
          boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
        }}>
          <div style={{ fontWeight: 600, marginBottom: 2 }}>
            <span style={{ color: DECISION_COLORS[ordered[hoveredIdx].decision] }}>
              {ordered[hoveredIdx].decision}
            </span>
            {' '}&mdash; risk {ordered[hoveredIdx].risk_score.toFixed(2)}
          </div>
          <div style={{ color: 'var(--text-muted)' }}>
            {ordered[hoveredIdx].action_type} &rarr; {ordered[hoveredIdx].target_asset}
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>
            {new Date(ordered[hoveredIdx].timestamp).toLocaleString()}
          </div>
        </div>
      )}

      {/* Time labels */}
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)', marginTop: 4, padding: '0 4px' }}>
        <span>{ordered.length > 0 ? new Date(ordered[0].timestamp).toLocaleDateString() : ''}</span>
        <span>{events.length} events</span>
        <span>{ordered.length > 0 ? new Date(ordered[ordered.length - 1].timestamp).toLocaleDateString() : ''}</span>
      </div>
    </div>
  )
}
