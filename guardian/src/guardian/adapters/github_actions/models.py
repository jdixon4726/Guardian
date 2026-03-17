"""
GitHub Actions Adapter request/response models.

Models the deployment_protection_rule webhook payload from GitHub.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class GitHubDeploymentRequest(BaseModel):
    """GitHub deployment protection rule webhook payload."""
    action: str = ""                         # requested
    environment: str = ""                    # production, staging, etc.
    deployment_callback_url: str = ""        # URL to POST approval/rejection
    # Workflow context
    workflow_name: str = ""
    workflow_ref: str = ""                   # branch/tag ref
    run_id: int = 0
    run_number: int = 0
    # Actor context
    sender_login: str = ""                   # GitHub username
    sender_type: str = ""                    # User, Bot
    # Repository context
    repository_full_name: str = ""           # org/repo
    repository_visibility: str = ""          # public, private
    # Event that triggered the workflow
    triggering_event: str = ""               # push, pull_request, workflow_dispatch
    head_sha: str = ""
    head_branch: str = ""


class GitHubDeploymentResponse(BaseModel):
    """Guardian's evaluation result for a deployment request."""
    allowed: bool
    decision: str
    risk_score: float
    explanation: str
    entry_id: str
    environment: str = ""
