import { StrictMode, Component } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './index.css'
import App from './App.jsx'

class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          padding: 40, maxWidth: 600, margin: '80px auto',
          fontFamily: '-apple-system, sans-serif', color: '#e6edf3',
          background: '#161b2a', borderRadius: 12, border: '1px solid #30363d',
        }}>
          <h2 style={{ color: '#FF453A', marginBottom: 12 }}>Guardian UI Error</h2>
          <p style={{ color: '#8b949e', marginBottom: 16 }}>The dashboard encountered an error. The API is still running.</p>
          <pre style={{
            background: '#0a0e1a', padding: 16, borderRadius: 8, fontSize: 12,
            overflow: 'auto', color: '#f85149', whiteSpace: 'pre-wrap',
          }}>
            {this.state.error?.toString()}
          </pre>
          <button
            onClick={() => window.location.reload()}
            style={{
              marginTop: 16, padding: '8px 20px', background: '#0A84FF',
              color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer',
              fontSize: 14, fontWeight: 600,
            }}
          >
            Reload
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ErrorBoundary>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </ErrorBoundary>
  </StrictMode>,
)
