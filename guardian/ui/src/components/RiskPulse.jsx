/**
 * Risk Pulse — a live waveform showing Guardian's recent activity.
 *
 * Like a heart rate monitor for infrastructure governance.
 * Flat line = quiet. Spikes = activity. Red spikes = blocks.
 */
import { useState, useEffect, useRef } from 'react'
import { useApi } from '../hooks/useApi'

const MAX_POINTS = 60

export default function RiskPulse({ height = 48 }) {
  const canvasRef = useRef(null)
  const pointsRef = useRef([])
  const { data } = useApi('/v1/decisions/recent?limit=30', { autoRefresh: 5000 })
  const prevCountRef = useRef(0)

  // When new decisions arrive, add points to the waveform
  useEffect(() => {
    if (!data?.decisions) return
    const newCount = data.total
    if (newCount > prevCountRef.current && prevCountRef.current > 0) {
      // New decisions arrived — add their risk scores as spikes
      const newDecisions = data.decisions.slice(0, newCount - prevCountRef.current)
      for (const d of newDecisions.reverse()) {
        pointsRef.current.push({
          risk: d.risk_score,
          isBlock: d.decision === 'block',
          t: Date.now(),
        })
      }
    } else if (prevCountRef.current === 0 && data.decisions.length > 0) {
      // Initial load — seed with recent decisions
      for (const d of [...data.decisions].reverse().slice(-20)) {
        pointsRef.current.push({
          risk: d.risk_score,
          isBlock: d.decision === 'block',
          t: Date.now() - Math.random() * 60000,
        })
      }
    }
    prevCountRef.current = newCount

    // Trim to max points
    while (pointsRef.current.length > MAX_POINTS) {
      pointsRef.current.shift()
    }
  }, [data])

  // Add idle heartbeat points
  useEffect(() => {
    const interval = setInterval(() => {
      // Add a quiet baseline point every 2 seconds
      pointsRef.current.push({
        risk: 0.02 + Math.random() * 0.03, // subtle noise
        isBlock: false,
        t: Date.now(),
      })
      while (pointsRef.current.length > MAX_POINTS) {
        pointsRef.current.shift()
      }
    }, 2000)
    return () => clearInterval(interval)
  }, [])

  // Canvas render loop
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    let animId

    const render = () => {
      const w = canvas.width
      const h = canvas.height
      const points = pointsRef.current

      ctx.clearRect(0, 0, w, h)

      if (points.length < 2) {
        animId = requestAnimationFrame(render)
        return
      }

      // Draw the waveform
      const step = w / (MAX_POINTS - 1)

      // Gradient fill under the line
      const gradient = ctx.createLinearGradient(0, 0, 0, h)
      gradient.addColorStop(0, 'rgba(88, 166, 255, 0.15)')
      gradient.addColorStop(1, 'rgba(88, 166, 255, 0)')

      ctx.beginPath()
      ctx.moveTo(0, h)

      for (let i = 0; i < points.length; i++) {
        const x = (i / (MAX_POINTS - 1)) * w
        const y = h - (points[i].risk * h * 0.9)
        if (i === 0) ctx.lineTo(x, y)
        else {
          // Smooth curve
          const prevX = ((i - 1) / (MAX_POINTS - 1)) * w
          const prevY = h - (points[i - 1].risk * h * 0.9)
          const cpX = (prevX + x) / 2
          ctx.bezierCurveTo(cpX, prevY, cpX, y, x, y)
        }
      }

      ctx.lineTo(((points.length - 1) / (MAX_POINTS - 1)) * w, h)
      ctx.closePath()
      ctx.fillStyle = gradient
      ctx.fill()

      // Draw the line
      ctx.beginPath()
      for (let i = 0; i < points.length; i++) {
        const x = (i / (MAX_POINTS - 1)) * w
        const y = h - (points[i].risk * h * 0.9)
        if (i === 0) ctx.moveTo(x, y)
        else {
          const prevX = ((i - 1) / (MAX_POINTS - 1)) * w
          const prevY = h - (points[i - 1].risk * h * 0.9)
          const cpX = (prevX + x) / 2
          ctx.bezierCurveTo(cpX, prevY, cpX, y, x, y)
        }
      }
      ctx.strokeStyle = 'rgba(88, 166, 255, 0.6)'
      ctx.lineWidth = 1.5
      ctx.stroke()

      // Draw block spikes as red dots
      for (let i = 0; i < points.length; i++) {
        if (points[i].isBlock) {
          const x = (i / (MAX_POINTS - 1)) * w
          const y = h - (points[i].risk * h * 0.9)
          ctx.beginPath()
          ctx.arc(x, y, 3, 0, Math.PI * 2)
          ctx.fillStyle = '#f85149'
          ctx.fill()
          // Glow
          ctx.beginPath()
          ctx.arc(x, y, 6, 0, Math.PI * 2)
          ctx.fillStyle = 'rgba(248, 81, 73, 0.3)'
          ctx.fill()
        }
      }

      animId = requestAnimationFrame(render)
    }

    render()
    return () => cancelAnimationFrame(animId)
  }, [])

  return (
    <div className="risk-pulse-container">
      <canvas
        ref={canvasRef}
        width={600}
        height={height}
        style={{ width: '100%', height, display: 'block' }}
      />
    </div>
  )
}
