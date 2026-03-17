"""
Guardian Onboarding — Discovery Engine + Auto-Configuration

Turns raw event streams into a fully configured Guardian deployment.
Instead of asking orgs to manually write YAML, Guardian observes
their environment and generates the configuration automatically.

Flow:
  1. Org connects cloud accounts (CloudTrail, Azure Activity Log, etc.)
  2. Discovery engine passively ingests events
  3. Auto-detects actors, assets, systems, and behavioral patterns
  4. Generates recommended config (actor registry, asset catalog, risk posture)
  5. Org reviews and activates

The discovery engine is the bridge between "impressive demo" and
"I can actually use this for my org."
"""
