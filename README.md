# Guardian

Guardian is an experimental security platform focused on machine identity visibility, operational invariants, and attack path intelligence.

The long-term goal of Guardian is to explore the concept of a living operational governance layer for modern organizations.

---

## Core Idea

Modern organizations operate across dozens of independent systems:

- Identity providers
- Cloud infrastructure
- CI/CD pipelines
- SaaS applications
- Automation workflows

Each system enforces policies independently, but no system understands the organization as a whole.

Guardian explores the concept of organizational invariants — rules that must always remain true across systems.

Examples include:

- Service accounts must have owners
- Terminated users must not retain access
- Privileged actions require authorization
