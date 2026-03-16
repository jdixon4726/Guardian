/**
 * Skeleton screens — show the shape of content before data arrives.
 * Research says this is the single most effective perceived-performance technique.
 */

export function SkeletonCard({ count = 3 }) {
  return (
    <div>
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="skeleton skeleton-card" />
      ))}
    </div>
  )
}

export function SkeletonStats({ count = 5 }) {
  return (
    <div className="stats-grid">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="skeleton skeleton-stat" />
      ))}
    </div>
  )
}

export function SkeletonText({ lines = 3 }) {
  return (
    <div className="card">
      {Array.from({ length: lines }).map((_, i) => (
        <div
          key={i}
          className={`skeleton skeleton-text ${i === lines - 1 ? 'short' : i === 0 ? 'full' : ''}`}
        />
      ))}
    </div>
  )
}
