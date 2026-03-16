"""
Kubernetes Admission Webhook request/response models.

Models the AdmissionReview objects exchanged between the K8s API server
and Guardian's validating webhook.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class AdmissionRequestUser(BaseModel):
    username: str = ""
    groups: list[str] = Field(default_factory=list)


class AdmissionRequestResource(BaseModel):
    group: str = ""
    version: str = ""
    resource: str = ""


class AdmissionRequestObject(BaseModel):
    """The object being admitted (pod spec, deployment spec, etc.)."""
    metadata: dict = Field(default_factory=dict)
    spec: dict = Field(default_factory=dict)
    kind: str = ""


class AdmissionRequest(BaseModel):
    uid: str
    kind: dict = Field(default_factory=dict)
    resource: AdmissionRequestResource = Field(default_factory=AdmissionRequestResource)
    namespace: str = "default"
    operation: str = ""  # CREATE, UPDATE, DELETE, CONNECT
    userInfo: AdmissionRequestUser = Field(default_factory=AdmissionRequestUser)
    object: AdmissionRequestObject | None = None
    oldObject: AdmissionRequestObject | None = None


class AdmissionReviewRequest(BaseModel):
    apiVersion: str = "admission.k8s.io/v1"
    kind: str = "AdmissionReview"
    request: AdmissionRequest


class AdmissionResponse(BaseModel):
    uid: str
    allowed: bool
    status: dict = Field(default_factory=dict)


class AdmissionReviewResponse(BaseModel):
    apiVersion: str = "admission.k8s.io/v1"
    kind: str = "AdmissionReview"
    response: AdmissionResponse
