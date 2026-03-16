/**
 * Micro-sparkline — tiny bar chart for inline trend visualization.
 * Darktrace uses these next to scores to show recent trend.
 */
export default function Sparkline({ values = [], height = 20, color = 'var(--accent)' }) {
  if (values.length === 0) return null
  const max = Math.max(...values, 1)

  return (
    <div className="sparkline" style={{ height }}>
      {values.map((v, i) => (
        <div
          key={i}
          className="sparkline-bar"
          style={{
            height: `${(v / max) * 100}%`,
            background: color,
            opacity: 0.4 + (i / values.length) * 0.6,
          }}
        />
      ))}
    </div>
  )
}
