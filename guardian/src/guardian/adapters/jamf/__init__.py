"""
Jamf Pro Adapter — Apple MDM Proxy Gateway

Intercepts destructive Jamf Pro device management API calls,
evaluates through Guardian's pipeline, and forwards or blocks.

Same proxy pattern as Intune, targeting Apple-heavy enterprises.
Jamf Pro REST API endpoints for device commands map directly
to Guardian's action taxonomy.
"""
