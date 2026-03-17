"""
GitHub Actions Adapter — Deployment Protection Rule Gate

Implements the GitHub deployment protection rule webhook protocol.
GitHub sends a deployment request to Guardian; Guardian evaluates
and responds with approve/deny.

This is the admission webhook pattern (like Kubernetes), not the
proxy pattern (like Intune). GitHub has native pre-execution hooks
via deployment environments.

Catches: supply chain attacks, workflow injection, unauthorized
deployments, branch protection bypass.
"""
