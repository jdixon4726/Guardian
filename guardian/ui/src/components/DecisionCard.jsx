/**
 * Decision summary card — Darktrace-inspired event card.
 * Shows risk gauge, decision badge, actor/action, and risk-colored left border.
 * Expands on click to show full detail panel with feedback controls.
 */
import { useState } from 'react'
import { postApi } from '../hooks/useApi'
import RiskGauge from './RiskGauge'

const DECISION_COLORS = {
  block: 'var(--red)',
  require_review: 'var(--yellow)',
  allow_with_logging: 'var(--accent)',
  allow: 'var(--green)',
}

const DECISION_ICONS = {
  block: '\u2718',
  require_review: '\u26A0',
  allow_with_logging: '\u2139',
  allow: '\u2714',
}

export default function DecisionCard({ entry, isExpanded, onToggle }) {
  const [feedbackSent, setFeedbackSent] = useState(false)
  const [feedbackType, setFeedbackType] = useState('')

  const borderColor = DECISION_COLORS[entry.decision] || 'var(--border)'
  const icon = DECISION_ICONS[entry.decision] || '?'

  const sendFeedback = async (type) => {
    try {
      await postApi(`/v1/decisions/${entry.entry_id}/feedback`, {
        feedback_type: type,
        operator: 'dashboard-user',
        reason: '',
      })
      setFeedbackType(type)
      setFeedbackSent(true)
    } catch (e) {
      console.error('Feedback failed:', e)
    }
  }

  const glowClass = entry.decision === 'block' ? ' critical'
    : entry.risk_score >= 0.6 ? ' high-risk' : ''

  return (
    <div
      className={`decision-card${glowClass}`}
      style={{
        borderLeft: `3px solid ${borderColor}`,
        background: 'var(--surface)',
        borderRadius: 'var(--radius)',
        marginBottom: 8,
        overflow: 'hidden',
        transition: 'all 0.2s ease',
        border: `1px solid ${isExpanded ? borderColor : 'var(--border)'}`,
        borderLeftWidth: 3,
        borderLeftColor: borderColor,
      }}
    >
      {/* Summary row */}
      <div
        onClick={onToggle}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 16,
          padding: '12px 16px',
          cursor: 'pointer',
          transition: 'background 0.15s',
        }}
        onMouseEnter={e => e.currentTarget.style.background = 'var(--surface-hover)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
      >
        <RiskGauge score={entry.risk_score} size={44} />

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
            <span className={`badge badge-${entry.decision}`}>
              {icon} {entry.decision.replace(/_/g, ' ')}
            </span>
            <span className={`badge badge-${entry.risk_band}`}>{entry.risk_band}</span>
          </div>
          <div style={{ fontSize: 14 }}>
            <span style={{ fontFamily: 'var(--mono)', color: 'var(--accent)' }}>{entry.actor_name}</span>
            <span style={{ color: 'var(--text-muted)', margin: '0 6px' }}>&rarr;</span>
            <span style={{ color: 'var(--text)' }}>{entry.action}</span>
            <span style={{ color: 'var(--text-muted)', margin: '0 6px' }}>on</span>
            <span style={{ fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>{entry.target_asset}</span>
          </div>
        </div>

        <div style={{ textAlign: 'right', flexShrink: 0 }}>
          {entry.drift_score != null && entry.drift_score > 0 && (
            <div style={{ fontSize: 11, color: 'var(--orange)', marginBottom: 2 }}>
              drift {entry.drift_score.toFixed(2)}
            </div>
          )}
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {new Date(entry.evaluated_at).toLocaleTimeString()}
          </div>
        </div>

        <div style={{ color: 'var(--text-muted)', fontSize: 18, transform: isExpanded ? 'rotate(180deg)' : 'rotate(0)', transition: 'transform 0.2s' }}>
          &#x25BE;
        </div>
      </div>

      {/* Expanded detail panel */}
      {isExpanded && (
        <div style={{
          borderTop: `1px solid var(--border)`,
          padding: 16,
          background: 'var(--bg)',
          animation: 'slideDown 0.2s ease',
        }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Actor</div>
              <div style={{ fontSize: 14, fontFamily: 'var(--mono)', marginTop: 4 }}>{entry.actor_name}</div>
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Action</div>
              <div style={{ fontSize: 14, fontFamily: 'var(--mono)', marginTop: 4 }}>{entry.action}</div>
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Target</div>
              <div style={{ fontSize: 14, fontFamily: 'var(--mono)', marginTop: 4 }}>{entry.target_asset}</div>
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Risk Score</div>
              <div style={{ fontSize: 20, fontFamily: 'var(--mono)', fontWeight: 700, marginTop: 4, color: borderColor }}>
                {entry.risk_score.toFixed(3)}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Drift Score</div>
              <div style={{ fontSize: 20, fontFamily: 'var(--mono)', fontWeight: 700, marginTop: 4 }}>
                {entry.drift_score != null ? entry.drift_score.toFixed(3) : 'N/A'}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Evaluated</div>
              <div style={{ fontSize: 14, marginTop: 4 }}>{new Date(entry.evaluated_at).toLocaleString()}</div>
            </div>
          </div>

          <div style={{ marginTop: 16, paddingTop: 12, borderTop: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 12, color: 'var(--text-muted)', marginRight: 4 }}>Feedback:</span>
            {feedbackSent ? (
              <span style={{ color: 'var(--green)', fontSize: 13 }}>
                &#x2714; {feedbackType.replace(/_/g, ' ')}
              </span>
            ) : (
              <>
                <button className="secondary" style={{ fontSize: 11, padding: '3px 10px' }}
                  onClick={() => sendFeedback('confirmed_correct')}>&#x2714; Correct</button>
                <button className="secondary" style={{ fontSize: 11, padding: '3px 10px', borderColor: 'var(--red)', color: 'var(--red)' }}
                  onClick={() => sendFeedback('false_positive')}>False Positive</button>
                <button className="secondary" style={{ fontSize: 11, padding: '3px 10px', borderColor: 'var(--orange)', color: 'var(--orange)' }}
                  onClick={() => sendFeedback('false_negative')}>False Negative</button>
                <button className="secondary" style={{ fontSize: 11, padding: '3px 10px', borderColor: 'var(--purple)', color: 'var(--purple)' }}
                  onClick={() => sendFeedback('known_pattern')}>Known Pattern</button>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
