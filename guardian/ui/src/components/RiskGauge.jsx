/**
 * Radial risk gauge — Darktrace-inspired visual risk indicator.
 * Shows risk score as a circular arc with color gradient.
 */
export default function RiskGauge({ score, size = 48, strokeWidth = 4 }) {
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const progress = score * circumference
  const rotation = -90

  const color = score >= 0.8 ? 'var(--red)'
    : score >= 0.6 ? 'var(--orange)'
    : score >= 0.3 ? 'var(--yellow)'
    : 'var(--green)'

  return (
    <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
      <svg width={size} height={size} style={{ transform: `rotate(${rotation}deg)` }}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--border)"
          strokeWidth={strokeWidth}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={circumference - progress}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.6s ease, stroke 0.3s ease' }}
        />
      </svg>
      <div style={{
        position: 'absolute',
        inset: 0,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: 'var(--mono)',
        fontSize: size * 0.24,
        fontWeight: 700,
        color,
      }}>
        {(score * 100).toFixed(0)}
      </div>
    </div>
  )
}
