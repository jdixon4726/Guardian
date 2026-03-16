import { useEffect, useRef, useState } from 'react'
import { useApi } from '../hooks/useApi'
import cytoscape from 'cytoscape'
import fcose from 'cytoscape-fcose'

cytoscape.use(fcose)

const NODE_COLORS = {
  actor: '#58a6ff',
  action: '#bc8cff',
  target: '#3fb950',
  system: '#d29922',
  decision: '#8b949e',
}

export default function AutomationGraph() {
  const containerRef = useRef(null)
  const cyRef = useRef(null)
  const [selectedNode, setSelectedNode] = useState(null)

  const { data: stats } = useApi('/v1/graph/stats')
  const { data: cascades } = useApi('/v1/graph/cascades?min_depth=2&limit=50')

  // Build graph from cascade data
  useEffect(() => {
    if (!containerRef.current || !cascades?.cascades) return

    const elements = []
    const nodeSet = new Set()

    // Get CSS variable values for current theme
    const style = getComputedStyle(document.documentElement)
    const textColor = style.getPropertyValue('--text').trim() || '#e6edf3'
    const bgColor = style.getPropertyValue('--bg').trim() || '#0d1117'
    const borderColor = style.getPropertyValue('--border').trim() || '#30363d'

    cascades.cascades.forEach(cascade => {
      cascade.actors.forEach(actorId => {
        if (!nodeSet.has(actorId)) {
          nodeSet.add(actorId)
          elements.push({
            data: {
              id: actorId,
              label: actorId.replace('actor:', ''),
              type: 'actor',
            }
          })
        }
      })

      cascade.systems.forEach(sysId => {
        if (!nodeSet.has(sysId)) {
          nodeSet.add(sysId)
          elements.push({
            data: {
              id: sysId,
              label: sysId.replace('system:', ''),
              type: 'system',
            }
          })
        }
      })

      // Create edges between consecutive actors through systems
      for (let i = 0; i < cascade.actors.length - 1; i++) {
        const edgeId = `${cascade.actors[i]}->${cascade.actors[i + 1]}`
        if (!nodeSet.has(edgeId)) {
          nodeSet.add(edgeId)
          elements.push({
            data: {
              id: edgeId,
              source: cascade.actors[i],
              target: cascade.actors[i + 1],
              risk: cascade.total_risk,
              label: `risk: ${cascade.total_risk.toFixed(2)}`,
            }
          })
        }
      }

      // Connect actors to systems
      cascade.actors.forEach((actorId, idx) => {
        if (idx < cascade.systems.length) {
          const sysEdgeId = `${actorId}->sys:${cascade.systems[idx]}`
          if (!nodeSet.has(sysEdgeId)) {
            nodeSet.add(sysEdgeId)
            elements.push({
              data: {
                id: sysEdgeId,
                source: actorId,
                target: cascade.systems[idx],
              }
            })
          }
        }
      })
    })

    if (elements.length === 0) return

    if (cyRef.current) cyRef.current.destroy()

    cyRef.current = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'font-size': 11,
            'font-family': '-apple-system, BlinkMacSystemFont, sans-serif',
            'color': textColor,
            'text-valign': 'bottom',
            'text-margin-y': 8,
            'width': 36,
            'height': 36,
            'border-width': 2,
            'border-color': borderColor,
          }
        },
        {
          selector: 'node[type="actor"]',
          style: {
            'background-color': NODE_COLORS.actor,
            'shape': 'ellipse',
            'width': 44,
            'height': 44,
          }
        },
        {
          selector: 'node[type="system"]',
          style: {
            'background-color': NODE_COLORS.system,
            'shape': 'round-rectangle',
            'width': 50,
            'height': 30,
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': borderColor,
            'target-arrow-color': '#8b949e',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.8,
          }
        },
        {
          selector: 'edge[risk]',
          style: {
            'width': 3,
            'line-color': '#f85149',
            'target-arrow-color': '#f85149',
          }
        },
        {
          selector: ':selected',
          style: {
            'border-color': '#58a6ff',
            'border-width': 3,
          }
        },
      ],
      layout: {
        name: 'fcose',
        animate: false,
        nodeDimensionsIncludeLabels: true,
        idealEdgeLength: 120,
        nodeRepulsion: 8000,
      },
    })

    cyRef.current.on('tap', 'node', (e) => {
      const node = e.target
      setSelectedNode({
        id: node.id(),
        label: node.data('label'),
        type: node.data('type'),
        degree: node.degree(),
      })
    })

    cyRef.current.on('tap', (e) => {
      if (e.target === cyRef.current) setSelectedNode(null)
    })

    // Breathing animation — nodes gently pulse
    let breathePhase = 0
    const breatheInterval = setInterval(() => {
      if (!cyRef.current) return
      breathePhase += 0.05
      cyRef.current.nodes().forEach(node => {
        const baseSize = node.data('type') === 'actor' ? 44 : node.data('type') === 'system' ? 50 : 36
        const breathe = Math.sin(breathePhase + node.id().length) * 2
        node.style('width', baseSize + breathe)
        node.style('height', node.data('type') === 'system' ? 30 + breathe * 0.5 : baseSize + breathe)
      })
    }, 100)

    return () => {
      clearInterval(breatheInterval)
      if (cyRef.current) cyRef.current.destroy()
    }
  }, [cascades])

  return (
    <div>
      <div className="page-header">
        <h1>Automation Graph</h1>
        <p>Visualize how automation flows across systems</p>
      </div>

      {stats && (
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-value">{stats.nodes_by_type?.actors || 0}</div>
            <div className="stat-label">Actors</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{stats.nodes_by_type?.systems || 0}</div>
            <div className="stat-label">Systems</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{stats.nodes_by_type?.targets || 0}</div>
            <div className="stat-label">Targets</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{stats.edges_by_type?.triggered || 0}</div>
            <div className="stat-label">Cascades</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{stats.total_events || 0}</div>
            <div className="stat-label">Total Events</div>
          </div>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: selectedNode ? '1fr 280px' : '1fr', gap: 16 }}>
        <div className="graph-container" ref={containerRef} />

        {selectedNode && (
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              {selectedNode.type === 'actor' ? 'Actor' : 'System'}
            </div>
            <dl>
              <dt style={{ color: 'var(--text-muted)', fontSize: 12 }}>Name</dt>
              <dd style={{ fontFamily: 'var(--mono)', marginBottom: 8 }}>{selectedNode.label}</dd>
              <dt style={{ color: 'var(--text-muted)', fontSize: 12 }}>Type</dt>
              <dd style={{ marginBottom: 8 }}>{selectedNode.type}</dd>
              <dt style={{ color: 'var(--text-muted)', fontSize: 12 }}>Connections</dt>
              <dd>{selectedNode.degree}</dd>
            </dl>
          </div>
        )}
      </div>

      {(!cascades?.cascades || cascades.cascades.length === 0) && (
        <div className="card" style={{ textAlign: 'center', padding: 60, color: 'var(--text-muted)', marginTop: 16 }}>
          No automation cascades detected yet. Cascades appear when Guardian observes
          cross-system automation chains.
        </div>
      )}
    </div>
  )
}
