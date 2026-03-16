/**
 * Heartbeat — a living pulse indicator that shows Guardian is active.
 *
 * Pulses gently when idle (I am watching).
 * Brightens on recent evaluation (I just made a decision).
 * Shows time since last evaluation.
 */
import { useState, useEffect } from 'react'
import { useApi } from '../hooks/useApi'

export default function Heartbeat() {
  const { data } = useApi('/v1/decisions/recent?limit=1', { autoRefresh: 5000 })
  const [lastEvalTime, setLastEvalTime] = useState(null)
  const [secondsAgo, setSecondsAgo] = useState(null)
  const [recentPulse, setRecentPulse] = useState(false)

  useEffect(() => {
    if (data?.decisions?.length > 0) {
      const evalTime = new Date(data.decisions[0].evaluated_at)
      const prevTime = lastEvalTime
      setLastEvalTime(evalTime)

      // Flash bright if this is a new decision we haven't seen
      if (prevTime && evalTime.getTime() > prevTime.getTime()) {
        setRecentPulse(true)
        setTimeout(() => setRecentPulse(false), 2000)
      }
    }
  }, [data])

  // Update seconds ago every second
  useEffect(() => {
    const interval = setInterval(() => {
      if (lastEvalTime) {
        setSecondsAgo(Math.floor((Date.now() - lastEvalTime.getTime()) / 1000))
      }
    }, 1000)
    return () => clearInterval(interval)
  }, [lastEvalTime])

  const formatAgo = (s) => {
    if (s === null) return 'waiting...'
    if (s < 5) return 'just now'
    if (s < 60) return `${s}s ago`
    if (s < 3600) return `${Math.floor(s / 60)}m ago`
    return `${Math.floor(s / 3600)}h ago`
  }

  return (
    <div className="heartbeat-container">
      <div className={`heartbeat-ring ${recentPulse ? 'active' : ''}`}>
        <div className="heartbeat-core" />
      </div>
      <div className="heartbeat-info">
        <div className="heartbeat-label">Last evaluation</div>
        <div className="heartbeat-time">{formatAgo(secondsAgo)}</div>
      </div>
    </div>
  )
}
