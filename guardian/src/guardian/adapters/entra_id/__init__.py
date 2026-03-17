"""
Microsoft Entra ID Admin Adapter — Identity Plane Proxy

Intercepts destructive Entra ID (Azure AD) admin operations through
Microsoft Graph API: user creation/deletion, role assignments,
conditional access policy changes, and federation modifications.

Extends the same Graph API proxy pattern used by the Intune adapter.
Directly addresses the Stryker root cause: the attacker's first move
was creating a rogue Global Administrator account in Entra ID.
"""
