import { useState, useEffect } from 'react'
import { useApi, postApi } from '../hooks/useApi'

const STEPS = [
  { id: 'industry', label: 'Select Industry', icon: '\u2630' },
  { id: 'connect', label: 'Connect Systems', icon: '\u26A1' },
  { id: 'discover', label: 'Discover Environment', icon: '\u2316' },
  { id: 'review', label: 'Review & Activate', icon: '\u2714' },
]

function StepIndicator({ currentStep }) {
  return (
    <div style={{ display: 'flex', gap: 0, marginBottom: 32 }}>
      {STEPS.map((step, i) => {
        const isActive = i === currentStep
        const isDone = i < currentStep
        return (
          <div key={step.id} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', position: 'relative' }}>
            {i > 0 && (
              <div style={{
                position: 'absolute', top: 16, left: '-50%', right: '50%', height: 2,
                background: isDone ? 'var(--green)' : 'var(--border)',
              }} />
            )}
            <div style={{
              width: 32, height: 32, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 14, fontWeight: 700, zIndex: 1,
              background: isDone ? 'var(--green)' : isActive ? 'var(--accent)' : 'var(--surface)',
              color: isDone || isActive ? '#fff' : 'var(--text-muted)',
              border: `2px solid ${isDone ? 'var(--green)' : isActive ? 'var(--accent)' : 'var(--border)'}`,
            }}>
              {isDone ? '\u2714' : step.icon}
            </div>
            <div style={{ fontSize: 11, marginTop: 6, color: isActive ? 'var(--text)' : 'var(--text-muted)', fontWeight: isActive ? 600 : 400 }}>
              {step.label}
            </div>
          </div>
        )
      })}
    </div>
  )
}

function IndustryStep({ selected, onSelect }) {
  const industries = [
    { id: 'healthcare', label: 'Healthcare', desc: 'HIPAA, device management, PHI protection', icon: '\u2695' },
    { id: 'fintech', label: 'Financial Services', desc: 'PCI-DSS, SOX, data exfiltration focus', icon: '\u2616' },
    { id: 'saas', label: 'SaaS / Software', desc: 'CI/CD governance, AI agent controls', icon: '\u2601' },
    { id: 'government', label: 'Government', desc: 'FedRAMP, NIST 800-53, maximum scrutiny', icon: '\u2691' },
    { id: 'general', label: 'General', desc: 'Balanced defaults for any organization', icon: '\u2699' },
  ]

  return (
    <div>
      <h3 style={{ marginBottom: 4 }}>What industry is your organization in?</h3>
      <p style={{ color: 'var(--text-muted)', fontSize: 14, marginBottom: 20 }}>
        This configures Guardian's risk thresholds, compliance frameworks, and recommended adapters for your industry.
      </p>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 12 }}>
        {industries.map(ind => (
          <div
            key={ind.id}
            onClick={() => onSelect(ind.id)}
            className="card"
            style={{
              cursor: 'pointer', padding: 16, marginBottom: 0,
              borderColor: selected === ind.id ? 'var(--accent)' : 'var(--border)',
              boxShadow: selected === ind.id ? '0 0 0 2px var(--accent)' : 'var(--shadow-ambient)',
            }}
          >
            <div style={{ fontSize: 24, marginBottom: 8 }}>{ind.icon}</div>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 4 }}>{ind.label}</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.4 }}>{ind.desc}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

function ConnectStep({ onIngest }) {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)

  const loadDemoData = async () => {
    setLoading(true)
    try {
      const res = await postApi('/v1/ingest/demo', {})
      // Also feed events into discovery engine
      setResult(res)
      if (onIngest) onIngest()
    } catch (err) {
      setResult({ error: err.message })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <h3 style={{ marginBottom: 4 }}>Connect your systems</h3>
      <p style={{ color: 'var(--text-muted)', fontSize: 14, marginBottom: 20 }}>
        Guardian discovers your environment by observing events from your cloud accounts, CI/CD pipelines, and identity providers.
      </p>

      <div className="card" style={{ marginBottom: 12 }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Cloud Accounts</div>
        <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 12 }}>
          Connect AWS (CloudTrail), Azure (Activity Log), or GCP (Audit Log). Guardian passively ingests events and auto-discovers your actors, assets, and systems.
        </p>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="secondary" style={{ fontSize: 12, opacity: 0.5 }}>Connect AWS</button>
          <button className="secondary" style={{ fontSize: 12, opacity: 0.5 }}>Connect Azure</button>
          <button className="secondary" style={{ fontSize: 12, opacity: 0.5 }}>Connect GCP</button>
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
          Cloud connectors coming soon. Use demo data or the API to ingest events.
        </div>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Automation Platforms</div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {['Terraform Cloud', 'Kubernetes', 'GitHub Actions', 'Intune', 'Entra ID', 'Jamf Pro'].map(p => (
            <span key={p} style={{ fontSize: 12, padding: '4px 10px', borderRadius: 'var(--radius-pill)', border: '1px solid var(--border)', color: 'var(--text-muted)' }}>
              {p}
            </span>
          ))}
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
          See <a href="/docs" style={{ color: 'var(--accent)' }}>API docs</a> for webhook setup instructions.
        </div>
      </div>

      <div className="card" style={{ borderColor: 'var(--accent)', borderLeftWidth: 3 }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Quick Start: Load Demo Data</div>
        <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 12 }}>
          Load 11 real-world attack scenarios (Stryker wiper, SolarWinds, Uber breach, and more) to see Guardian in action immediately.
        </p>
        <button onClick={loadDemoData} disabled={loading} style={{ fontSize: 13 }}>
          {loading ? 'Loading...' : 'Load Demo Scenarios'}
        </button>
        {result && !result.error && (
          <div style={{ marginTop: 8, fontSize: 12, color: 'var(--green)' }}>
            Loaded {result.total_events} events from {result.scenarios_run?.length} scenarios.
          </div>
        )}
        {result?.error && (
          <div style={{ marginTop: 8, fontSize: 12, color: 'var(--red)' }}>Error: {result.error}</div>
        )}
      </div>
    </div>
  )
}

function DiscoverStep() {
  const { data: status, refetch } = useApi('/v1/onboard/status', { autoRefresh: 5000 })
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(false)

  const runDiscovery = async () => {
    setLoading(true)
    try {
      const res = await postApi('/v1/onboard/discover', {})
      setReport(res)
    } catch (err) {
      setReport({ error: err.message })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <h3 style={{ marginBottom: 4 }}>Discover your environment</h3>
      <p style={{ color: 'var(--text-muted)', fontSize: 14, marginBottom: 20 }}>
        Guardian analyzes ingested events to identify your actors, assets, and systems automatically.
      </p>

      {status && (
        <div style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-value" style={{ fontSize: 24 }}>{status.events_ingested || 0}</div>
            <div className="stat-label">Events</div>
          </div>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-value" style={{ fontSize: 24, color: 'var(--accent)' }}>{status.actors_discovered || 0}</div>
            <div className="stat-label">Actors</div>
          </div>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-value" style={{ fontSize: 24, color: 'var(--orange)' }}>{status.assets_discovered || 0}</div>
            <div className="stat-label">Assets</div>
          </div>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-value" style={{ fontSize: 24, color: 'var(--green)' }}>{status.systems_discovered || 0}</div>
            <div className="stat-label">Systems</div>
          </div>
        </div>
      )}

      <button onClick={runDiscovery} disabled={loading} style={{ marginBottom: 16 }}>
        {loading ? 'Analyzing...' : 'Run Discovery'}
      </button>

      {report && !report.error && (
        <div>
          <div className="card" style={{ marginBottom: 8 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>
              Recommended Risk Posture: <span style={{ color: 'var(--accent)' }}>{report.recommended_risk_posture}</span>
            </div>
            <div style={{ fontSize: 14, fontWeight: 600 }}>
              Recommended Adapters: {(report.recommended_adapters || []).join(', ') || 'none'}
            </div>
          </div>

          {report.actors && report.actors.length > 0 && (
            <div className="card" style={{ padding: 0, overflow: 'hidden', marginBottom: 8 }}>
              <div style={{ padding: '12px 16px', fontWeight: 600, fontSize: 14, borderBottom: '1px solid var(--border)' }}>
                Discovered Actors ({report.actors.length})
              </div>
              <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th style={{ padding: '6px 12px', textAlign: 'left', color: 'var(--text-muted)' }}>Name</th>
                    <th style={{ padding: '6px 12px', textAlign: 'left', color: 'var(--text-muted)' }}>Type</th>
                    <th style={{ padding: '6px 12px', textAlign: 'right', color: 'var(--text-muted)' }}>Events</th>
                    <th style={{ padding: '6px 12px', textAlign: 'left', color: 'var(--text-muted)' }}>Max Privilege</th>
                  </tr>
                </thead>
                <tbody>
                  {report.actors.slice(0, 15).map(a => (
                    <tr key={a.name} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '6px 12px', fontFamily: 'var(--mono)' }}>{a.name}</td>
                      <td style={{ padding: '6px 12px' }}>
                        <span className={`badge badge-${a.actor_type === 'ai_agent' ? 'high' : a.actor_type === 'automation' ? 'medium' : 'low'}`}>
                          {a.actor_type}
                        </span>
                      </td>
                      <td style={{ padding: '6px 12px', textAlign: 'right', fontFamily: 'var(--mono)' }}>{a.event_count}</td>
                      <td style={{ padding: '6px 12px' }}>
                        <span style={{ color: a.recommended_max_privilege === 'admin' ? 'var(--red)' : a.recommended_max_privilege === 'elevated' ? 'var(--orange)' : 'var(--text-muted)' }}>
                          {a.recommended_max_privilege}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {report.systems && report.systems.length > 0 && (
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '12px 16px', fontWeight: 600, fontSize: 14, borderBottom: '1px solid var(--border)' }}>
                Discovered Systems ({report.systems.length})
              </div>
              <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th style={{ padding: '6px 12px', textAlign: 'left', color: 'var(--text-muted)' }}>System</th>
                    <th style={{ padding: '6px 12px', textAlign: 'right', color: 'var(--text-muted)' }}>Events</th>
                    <th style={{ padding: '6px 12px', textAlign: 'left', color: 'var(--text-muted)' }}>Adapter</th>
                  </tr>
                </thead>
                <tbody>
                  {report.systems.map(s => (
                    <tr key={s.system_id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '6px 12px', fontFamily: 'var(--mono)' }}>{s.system_id}</td>
                      <td style={{ padding: '6px 12px', textAlign: 'right', fontFamily: 'var(--mono)' }}>{s.event_count}</td>
                      <td style={{ padding: '6px 12px' }}>
                        {s.adapter_available
                          ? <span style={{ color: 'var(--green)' }}>{s.recommended_adapter}</span>
                          : <span style={{ color: 'var(--text-muted)' }}>—</span>
                        }
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function ReviewStep() {
  const [applying, setApplying] = useState(false)
  const [result, setResult] = useState(null)

  const activateGuardian = async () => {
    setApplying(true)
    try {
      const res = await postApi('/v1/onboard/apply', {})
      setResult(res)
    } catch (err) {
      setResult({ error: err.message })
    } finally {
      setApplying(false)
    }
  }

  return (
    <div>
      <h3 style={{ marginBottom: 4 }}>Review & Activate</h3>
      <p style={{ color: 'var(--text-muted)', fontSize: 14, marginBottom: 20 }}>
        Apply the discovered configuration to activate Guardian governance for your organization.
      </p>

      {!result ? (
        <div className="card" style={{ textAlign: 'center', padding: 40 }}>
          <div style={{ fontSize: 40, marginBottom: 12, opacity: 0.3 }}>{'\u2714'}</div>
          <h3 style={{ marginBottom: 8 }}>Ready to activate</h3>
          <p style={{ color: 'var(--text-muted)', fontSize: 14, marginBottom: 24, maxWidth: 400, marginInline: 'auto' }}>
            Guardian will register all discovered actors, configure risk scoring based on your industry template, and begin evaluating actions through the full behavioral pipeline.
          </p>
          <button onClick={activateGuardian} disabled={applying} style={{ padding: '12px 32px', fontSize: 15 }}>
            {applying ? 'Activating...' : 'Activate Guardian'}
          </button>
        </div>
      ) : result.error ? (
        <div className="error">{result.error}</div>
      ) : (
        <div className="card" style={{ borderColor: 'var(--green)', borderLeftWidth: 3 }}>
          <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--green)', marginBottom: 8 }}>
            {'\u2714'} Guardian Activated
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, marginTop: 16 }}>
            <div>
              <div style={{ fontSize: 24, fontWeight: 300, fontFamily: 'var(--mono)' }}>{result.actors_registered}</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Actors Registered</div>
            </div>
            <div>
              <div style={{ fontSize: 24, fontWeight: 300, fontFamily: 'var(--mono)' }}>{result.systems_discovered}</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Systems Monitored</div>
            </div>
            <div>
              <div style={{ fontSize: 24, fontWeight: 300, fontFamily: 'var(--mono)' }}>{result.assets_discovered}</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Assets Protected</div>
            </div>
          </div>
          <div style={{ marginTop: 16, fontSize: 13, color: 'var(--text-muted)' }}>
            Risk posture: <strong>{result.recommended_risk_posture}</strong> |
            Adapters: <strong>{(result.recommended_adapters || []).join(', ')}</strong>
          </div>
          <div style={{ marginTop: 16 }}>
            <a href="/" style={{ color: 'var(--accent)', fontWeight: 600 }}>Go to Command Center →</a>
          </div>
        </div>
      )}
    </div>
  )
}

export default function Onboarding() {
  const [step, setStep] = useState(0)
  const [industry, setIndustry] = useState('')
  const [templateApplied, setTemplateApplied] = useState(false)

  const applyTemplate = async () => {
    if (!industry) return
    try {
      await postApi('/v1/onboard/apply-template', { industry })
      setTemplateApplied(true)
      setStep(1)
    } catch (err) {
      console.error('Template apply failed:', err)
      setStep(1) // proceed anyway
    }
  }

  const nextStep = () => setStep(Math.min(step + 1, STEPS.length - 1))
  const prevStep = () => setStep(Math.max(step - 1, 0))

  return (
    <div>
      <div className="page-header">
        <h1>Setup Guardian</h1>
        <p>Configure Guardian for your organization in 4 steps</p>
      </div>

      <StepIndicator currentStep={step} />

      <div style={{ minHeight: 400 }}>
        {step === 0 && (
          <div>
            <IndustryStep selected={industry} onSelect={setIndustry} />
            <div style={{ marginTop: 24, display: 'flex', justifyContent: 'flex-end' }}>
              <button onClick={applyTemplate} disabled={!industry}>
                Apply Template & Continue →
              </button>
            </div>
          </div>
        )}

        {step === 1 && (
          <div>
            <ConnectStep onIngest={() => {}} />
            <div style={{ marginTop: 24, display: 'flex', justifyContent: 'space-between' }}>
              <button className="secondary" onClick={prevStep}>← Back</button>
              <button onClick={nextStep}>Continue to Discovery →</button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div>
            <DiscoverStep />
            <div style={{ marginTop: 24, display: 'flex', justifyContent: 'space-between' }}>
              <button className="secondary" onClick={prevStep}>← Back</button>
              <button onClick={nextStep}>Review & Activate →</button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div>
            <ReviewStep />
            <div style={{ marginTop: 24 }}>
              <button className="secondary" onClick={prevStep}>← Back</button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
