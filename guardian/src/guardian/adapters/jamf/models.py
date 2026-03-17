"""
Jamf Pro Adapter request/response models.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class JamfDeviceCommand(BaseModel):
    """Intercepted Jamf Pro device management command."""
    device_id: str = Field(..., min_length=1)
    command: str = Field(..., min_length=1)  # EraseDevice, Lock, etc.
    device_name: str = ""
    device_type: str = ""                    # computer, mobile_device
    serial_number: str = ""
    passcode: str = ""                       # for EraseDevice/Lock commands


class JamfProxyResponse(BaseModel):
    """Response returned when Guardian intercepts a Jamf command."""
    allowed: bool
    decision: str
    risk_score: float
    explanation: str
    entry_id: str
    circuit_breaker_tripped: bool = False
    circuit_breaker_reason: str | None = None
