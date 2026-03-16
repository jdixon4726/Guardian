/**
 * Decision Card — rich expandable card with risk gauge, severity tier,
 * "Why this decision?" explanation, and deep-link to Actor Intelligence.
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

// Generate a "Why this decision?" explanation from available signals
function generateExplanation(entry) {
  const parts = []

  if (entry.decision === 'block' && entry.risk_score >= 1.0) {
    parts.push(`This action was <strong>blocked by identity attestation</strong> — the actor either isn't registered, is terminated, or requested privileges beyond their maximum authorized level.`)
  } else if (entry.decision === 'block') {
    parts.push(`This action was <strong>blocked</strong> because the combined risk score (${entry.risk_score.toFixed(2)}) exceeded the block threshold.`)
  } else if (entry.decision === 'require_review') {
    if (entry.risk_score >= 0.5) {
      parts.push(`This action requires review because the <strong>risk score is elevated</strong> (${entry.risk_score.toFixed(2)}).`)
    } else {
      parts.push(`This action requires review — <strong>no policy rule explicitly allowed it</strong>, so Guardian defaults to requiring human approval.`)
    }
  } else if (entry.decision === 'allow_with_logging') {
    parts.push(`This action was allowed but <strong>flagged for logging</strong> due to moderate risk signals.`)
  } else {
    parts.push(`This action was <strong>allowed</strong> — it matched a permissive policy rule with low risk signals.`)
  }

  // Drift context
  if (entry.drift_score != null && entry.drift_score > 0.3) {
    parts.push(`Behavioral drift was detected (score: ${entry.drift_score.toFixed(2)}) — this actor's recent pattern deviates from its baseline.`)
  }

  return parts.join(' ')
}

// Recommended next step based on decision
function getNextStep(entry) {
  if (entry.decision === 'block' && entry.risk_score >= 1.0) {
    return 'Verify this actor exists in the actor registry and has appropriate privilege levels.'
  }
  if (entry.decision === 'block') {
    return 'Review the actor\'s recent activity for signs of compromise or misconfiguration.'
  }
  if (entry.decision === 'require_review' && entry.risk_score >= 0.5) {
    return 'Investigate the actor\'s behavioral profile before approving this action.'
  }
  if (entry.decision === 'require_review') {
    return 'Consider adding a policy rule to explicitly allow this action type if it is routine.'
  }
  return null
}

export default function DecisionCard({ entry, severity = 'info', isExpanded, onToggle, onNavigateToActor }) {
  const [feedbackSent, setFeedbackSent] = useState(false)
  const [feedbackType, setFeedbackType] = useState('')

  const borderColor = DECISION_COLORS[entry.decision] || 'var(--border)'
  const icon = DECISION_ICONS[entry.decision] || '?'
  const explanation = generateExplanation(entry)
  const nextStep = getNextStep(entry)

  const glowClass = severity === 'critical' ? ' critical' : severity === 'warning' ? ' high-risk' : ''

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

  return (
    <div
      className={`decision-card${glowClass}`}
      style={{
        borderLeft: `3px solid ${borderColor}`,
        background: 'var(--surface)',
        borderRadius: 'var(--radius)',
        marginBottom: 8,
        overflow: 'hidden',
        transition: 'border-color 0.15s, box-shadow 0.15s',
        border: `1px solid ${isExpanded ? borderColor : 'var(--border)'}`,
        borderLeftWidth: 3,
        borderLeftColor: borderColor,
        boxShadow: 'var(--shadow-ambient)',
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
          </div>
          <div style={{ fontSize: 14 }}>
            <span
              style={{ fontFamily: 'var(--mono)', color: 'var(--accent)', cursor: 'pointer' }}
              onClick={(e) => { e.stopPropagation(); onNavigateToActor?.() }}
              title="View actor profile"
            >
              {entry.actor_name}
            </span>
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
          <div style={{ fontSize: 12, color: 'var(--text-muted)', fontVariantNumeric: 'tabular-nums' }}>
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
          {/* Why this decision? — the most important element */}
          <div style={{
            padding: '10px 14px',
            background: 'var(--surface)',
            borderRadius: 'var(--radius-sm)',
            borderLeft: `3px solid ${borderColor}`,
            marginBottom: 14,
          }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>
              Why this decision
            </div>
            <div style={{ fontSize: 13, lineHeight: 1.6 }} dangerouslySetInnerHTML={{ __html: explanation }} />
            {nextStep && (
              <div style={{ fontSize: 12, color: 'var(--accent)', marginTop: 6 }}>
                <strong>Next step:</strong> {nextStep}
              </div>
            )}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, marginBottom: 14 }}>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Actor</div>
              <div
                style={{ fontSize: 14, fontFamily: 'var(--mono)', marginTop: 4, color: 'var(--accent)', cursor: 'pointer' }}
                onClick={onNavigateToActor}
                title="View full actor profile"
              >
                {entry.actor_name} &rarr;
              </div>
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
              <div style={{ fontSize: 20, fontFamily: 'var(--mono)', fontWeight: 700, marginTop: 4, color: borderColor, fontVariantNumeric: 'tabular-nums' }}>
                {entry.risk_score.toFixed(3)}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Drift Score</div>
              <div style={{ fontSize: 20, fontFamily: 'var(--mono)', fontWeight: 700, marginTop: 4, fontVariantNumeric: 'tabular-nums' }}>
                {entry.drift_score != null ? entry.drift_score.toFixed(3) : 'N/A'}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Evaluated</div>
              <div style={{ fontSize: 14, marginTop: 4, fontVariantNumeric: 'tabular-nums' }}>{new Date(entry.evaluated_at).toLocaleString()}</div>
            </div>
          </div>

          <div style={{ paddingTop: 12, borderTop: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8 }}>
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
