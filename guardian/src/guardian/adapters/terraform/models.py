"""
Terraform Cloud Run Task request/response models.

Models the webhook payload that Terraform Cloud sends to Guardian
and the callback response Guardian sends back.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class TFCRunTaskRequest(BaseModel):
    """Payload sent by Terraform Cloud to the run task callback URL."""
    payload_version: int = 1
    access_token: str
    stage: str = "post_plan"                  # post_plan | pre_apply
    is_speculative: bool = False
    task_result_callback_url: str
    task_result_enforcement_level: str = "advisory"  # advisory | mandatory
    run_id: str
    workspace_id: str
    workspace_name: str = ""
    organization_name: str = ""
    plan_json_api_url: str                    # URL to fetch the JSON plan
    vcs_repo_url: str = ""
    vcs_branch: str = ""
    vcs_pull_request_url: str = ""
    run_created_by: str = ""                  # email of the user who triggered


class TFCCallbackPayload(BaseModel):
    """Payload Guardian sends back to Terraform Cloud."""
    data: TFCCallbackData


class TFCCallbackData(BaseModel):
    type: str = "task-results"
    attributes: TFCCallbackAttributes


class TFCCallbackAttributes(BaseModel):
    status: str             # "passed" | "failed" | "running"
    message: str = ""
    url: str = ""           # optional link back to Guardian's UI/API
