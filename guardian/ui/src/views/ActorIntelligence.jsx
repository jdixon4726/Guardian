import { useState } from 'react'
import { useApi } from '../hooks/useApi'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import RiskGauge from '../components/RiskGauge'
import PeerBar from '../components/PeerBar'
import Sparkline from '../components/Sparkline'
import ActivityTimeline from '../components/ActivityTimeline'
import PatternOfLife from '../components/PatternOfLife'
import CascadeContext from '../components/CascadeContext'

function InsightCard({ severity, title, narrative }) {
  const borderColor = severity === 'critical' ? 'var(--red)'
    : severity === 'high' ? 'var(--orange)'
    : severity === 'medium' ? 'var(--yellow)'
    : 'var(--accent)'

  return (
    <div className="insight-card" style={{ borderLeftColor: borderColor }}>
      <div className="insight-title">
        <span className={`badge badge-${severity}`}>{severity}</span>
        {title}
      </div>
      <div className="insight-narrative" dangerouslySetInnerHTML={{ __html: narrative }} />
    </div>
  )
}

function generateInsights(profile, scopeDrift) {
  const insights = []

  if (profile.trust_level < 0.3) {
    insights.push({
      severity: 'critical',
      title: 'Low trust actor',
      narrative: `<strong>${profile.actor_name}</strong> has a trust level of ${(profile.trust_level * 100).toFixed(0)}%, well below the typical range. This actor has been blocked <strong>${profile.total_blocks} times</strong> and flagged for review <strong>${profile.total_reviews} times</strong>. Investigate recent activity for potential compromise or misconfiguration.`,
    })
  }

  if (profile.total_blocks > 0 && profile.total_actions > 0) {
    const blockRate = profile.total_blocks / profile.total_actions
    if (blockRate > 0.3) {
      insights.push({
        severity: 'high',
        title: 'High block rate',
        narrative: `<strong>${(blockRate * 100).toFixed(0)}%</strong> of this actor's requests have been blocked. ${profile.total_blocks} out of ${profile.total_actions} total actions were denied. This pattern suggests the actor may be operating outside its authorized scope.`,
      })
    }
  }

  if (scopeDrift?.is_drifting) {
    insights.push({
      severity: 'high',
      title: 'Scope drift detected',
      narrative: `<strong>${profile.actor_name}</strong> has expanded into <strong>${scopeDrift.new_targets?.length || 0} new targets</strong> and <strong>${scopeDrift.new_systems?.length || 0} new systems</strong> that it has never operated in before. This behavioral change deviates from its established pattern of life.`,
    })
  }

  if (profile.actions_last_hour > 20) {
    insights.push({
      severity: 'medium',
      title: 'Elevated velocity',
      narrative: `<strong>${profile.actions_last_hour} actions</strong> in the last hour is significantly above typical rates. Check if this corresponds to a known deployment or migration.`,
    })
  }

  if (insights.length === 0 && profile.total_actions > 0) {
    insights.push({
      severity: 'low',
      title: 'Normal behavioral pattern',
      narrative: `<strong>${profile.actor_name}</strong> is operating within its established behavioral pattern. Trust level is ${profile.trust_band}, with ${profile.total_actions} actions over ${profile.history_days} days. No anomalies detected.`,
    })
  }

  return insights
}

export default function ActorIntelligence() {
  const [actorName, setActorName] = useState('')
  const [searchName, setSearchName] = useState('')

  const { data: profile, loading, error } = useApi(
    `/v1/actors/${searchName}/profile`,
    { enabled: !!searchName }
  )

  const { data: targets } = useApi(
    `/v1/graph/actor/${searchName}/targets`,
    { enabled: !!searchName }
  )

  const { data: scopeDrift } = useApi(
    `/v1/graph/actor/${searchName}/scope-drift`,
    { enabled: !!searchName }
  )

  const { data: blastRadius } = useApi(
    `/v1/graph/actor/${searchName}/blast-radius`,
    { enabled: !!searchName }
  )

  const { data: timeline } = useApi(
    `/v1/actors/${searchName}/timeline?limit=150`,
    { enabled: !!searchName }
  )

  const { data: pattern } = useApi(
    `/v1/actors/${searchName}/pattern`,
    { enabled: !!searchName }
  )

  const handleSearch = (e) => {
    e.preventDefault()
    setSearchName(actorName)
  }

  const topActionsData = profile?.top_actions
    ? Object.entries(profile.top_actions).map(([name, count]) => ({ name, count }))
    : []

  const insights = profile ? generateInsights(profile, scopeDrift) : []

  // Simulate sparkline data from available stats
  const velocitySparkline = profile ? [
    Math.max(1, profile.total_allows - 3),
    profile.total_allows - 1,
    profile.total_allows,
    profile.actions_last_day,
    profile.actions_last_hour * 4,
  ] : []

  return (
    <div>
      <div className="page-header">
        <h1>Actor Intelligence</h1>
        <p>Behavioral profile, trust trajectory, and anomaly analysis</p>
      </div>

      <form onSubmit={handleSearch} className="filters">
        <input
          placeholder="Enter actor name..."
          value={actorName}
          onChange={e => setActorName(e.target.value)}
          style={{ width: 300 }}
        />
        <button type="submit">Analyze</button>
      </form>

      {error && <div className="error">{error}</div>}
      {loading && <div className="loading">Loading profile...</div>}

      {profile && (
        <>
          {/* AI Analyst-style behavioral insights */}
          {insights.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              {insights.map((insight, i) => (
                <InsightCard key={i} {...insight} />
              ))}
            </div>
          )}

          {/* Top stats with risk gauge */}
          <div style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
            <div className="stat-card" style={{ flex: '0 0 auto', display: 'flex', alignItems: 'center', gap: 16, padding: '16px 24px' }}>
              <RiskGauge score={1 - profile.trust_level} size={64} strokeWidth={6} />
              <div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Risk Level</div>
                <div style={{ fontSize: 20, fontWeight: 700 }}>
                  {profile.trust_band === 'high' ? 'Low' : profile.trust_band === 'neutral' ? 'Medium' : 'High'}
                </div>
              </div>
            </div>
            <div className="stat-card" style={{ flex: 1 }}>
              <div className="stat-value">{profile.total_actions}</div>
              <div className="stat-label">Total Actions</div>
              <Sparkline values={velocitySparkline} color="var(--accent)" />
            </div>
            <div className="stat-card" style={{ flex: 1 }}>
              <div className="stat-value" style={{ color: 'var(--green)' }}>{profile.total_allows}</div>
              <div className="stat-label">Allows</div>
            </div>
            <div className="stat-card" style={{ flex: 1 }}>
              <div className="stat-value" style={{ color: 'var(--yellow)' }}>{profile.total_reviews}</div>
              <div className="stat-label">Reviews</div>
            </div>
            <div className="stat-card" style={{ flex: 1 }}>
              <div className="stat-value" style={{ color: 'var(--red)' }}>{profile.total_blocks}</div>
              <div className="stat-label">Blocks</div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
            {/* Trust with peer context */}
            <div className="card">
              <div className="card-header">
                <span className="card-title">Trust Level</span>
                <span className={`badge badge-${profile.trust_band === 'high' ? 'allow' : profile.trust_band === 'neutral' ? 'require_review' : 'block'}`}>
                  {profile.trust_band}
                </span>
              </div>
              <PeerBar
                value={profile.trust_level}
                peerMin={0.4}
                peerMax={0.85}
                label="Trust vs. peer group"
              />
              <div style={{ marginTop: 12, fontSize: 13, color: 'var(--text-muted)' }}>
                History: {profile.history_days} days | Velocity: {profile.actions_last_hour}/hr, {profile.actions_last_day}/day
                {profile.first_seen && <> | First seen: {new Date(profile.first_seen).toLocaleDateString()}</>}
              </div>
            </div>

            {/* Blast radius + scope drift */}
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Operational Scope</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                {blastRadius && (
                  <>
                    <div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Blast Radius</div>
                      <div style={{ fontSize: 20, fontWeight: 700, fontFamily: 'var(--mono)', color: blastRadius.blast_radius_score >= 0.5 ? 'var(--orange)' : 'var(--text)' }}>
                        {(blastRadius.blast_radius_score * 100).toFixed(0)}%
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Targets</div>
                      <div style={{ fontSize: 14 }}>
                        {blastRadius.direct_targets} direct, {blastRadius.indirect_targets} indirect
                      </div>
                    </div>
                  </>
                )}
                {scopeDrift && (
                  <>
                    <div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Scope Drift</div>
                      <div style={{ fontSize: 20, fontWeight: 700, fontFamily: 'var(--mono)', color: scopeDrift.is_drifting ? 'var(--red)' : 'var(--green)' }}>
                        {scopeDrift.scope_drift_score.toFixed(2)}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>New Targets</div>
                      <div style={{ fontSize: 14, color: (scopeDrift.new_targets?.length || 0) > 0 ? 'var(--orange)' : 'var(--text-muted)' }}>
                        {scopeDrift.new_targets?.length || 0} targets, {scopeDrift.new_systems?.length || 0} systems
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Activity Timeline */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Activity Timeline</span>
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                Risk-weighted | height = risk score
              </span>
            </div>
            <ActivityTimeline events={timeline?.events || []} />
          </div>

          {/* Pattern of Life + Cascade Context */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Pattern of Life</div>
              <PatternOfLife pattern={pattern?.pattern || []} />
            </div>

            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Automation Chains</div>
              <CascadeContext actorName={searchName} />
            </div>
          </div>

          {topActionsData.length > 0 && (
            <div className="card">
              <div className="card-title" style={{ marginBottom: 16 }}>Action Distribution</div>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={topActionsData} layout="vertical" margin={{ left: 140 }}>
                  <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                  <XAxis type="number" />
                  <YAxis dataKey="name" type="category" tick={{ fontSize: 12, fill: 'var(--text-muted)' }} width={130} />
                  <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)' }} />
                  <Bar dataKey="count" fill="var(--accent)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {targets?.targets?.length > 0 && (
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Targets Affected</div>
              <table className="table">
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>System</th>
                    <th>Frequency</th>
                    <th>Avg Risk</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {targets.targets.slice(0, 15).map(t => (
                    <tr key={t.target_id}>
                      <td style={{ fontFamily: 'var(--mono)', fontSize: 13 }}>{t.target_name}</td>
                      <td>{t.target_system}</td>
                      <td>{t.frequency}</td>
                      <td>
                        <span style={{ fontFamily: 'var(--mono)', color: t.avg_risk >= 0.6 ? 'var(--orange)' : 'var(--text-muted)' }}>
                          {t.avg_risk?.toFixed(3) || '-'}
                        </span>
                      </td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 13 }}>
                        {t.last_seen ? new Date(t.last_seen).toLocaleDateString() : '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {!profile && !loading && !error && (
        <div className="card" style={{ textAlign: 'center', padding: 60, color: 'var(--text-muted)' }}>
          Enter an actor name to view their behavioral profile and threat assessment.
          <div style={{ marginTop: 12, fontSize: 13 }}>
            Try: <code style={{ background: 'var(--bg)', padding: '2px 6px', borderRadius: 4, cursor: 'pointer' }}
              onClick={() => { setActorName('deploy-bot-prod'); setSearchName('deploy-bot-prod') }}>deploy-bot-prod</code>
            {' '}<code style={{ background: 'var(--bg)', padding: '2px 6px', borderRadius: 4, cursor: 'pointer' }}
              onClick={() => { setActorName('ai-remediation-bot'); setSearchName('ai-remediation-bot') }}>ai-remediation-bot</code>
            {' '}<code style={{ background: 'var(--bg)', padding: '2px 6px', borderRadius: 4, cursor: 'pointer' }}
              onClick={() => { setActorName('terraform-cloud-runner'); setSearchName('terraform-cloud-runner') }}>terraform-cloud-runner</code>
          </div>
        </div>
      )}
    </div>
  )
}
