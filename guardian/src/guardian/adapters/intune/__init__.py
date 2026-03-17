"""
Microsoft Intune Adapter — UEM Proxy Gateway

Intercepts destructive Microsoft Graph device management API calls,
evaluates them through Guardian's pipeline, and forwards or blocks
based on the decision.

Unlike Terraform (async callback) or Kubernetes (admission webhook),
Intune has no native pre-execution hook. Guardian acts as the enforcement
point directly — a secure proxy that only forwards allowed actions.

Motivated by the March 2026 Stryker incident: an attacker weaponized
Intune's legitimate Remote Wipe feature to factory-reset 200,000+ devices
using compromised Global Admin credentials.
"""
