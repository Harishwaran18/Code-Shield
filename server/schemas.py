"""Request and response models."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from server.security.passwords import validate_password_strength

Language = Literal["python", "javascript", "typescript", "java", "go", "other"]


class RegisterRequest(BaseModel):
    email: EmailStr
    name: str = Field(min_length=2, max_length=80)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = " ".join(value.split())
        if not value or any(ord(char) < 32 for char in value):
            raise ValueError("Name contains invalid characters")
        return value

    @field_validator("password")
    @classmethod
    def strong_password(cls, value: str) -> str:
        validate_password_strength(value)
        return value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: EmailStr
    name: str
    role: str
    created_at: datetime


class SessionOut(BaseModel):
    id: str
    user_id: str
    user_name: str
    ip: str
    device: str
    created_at: datetime
    last_seen_at: datetime
    verified: bool
    risk_score: float
    anomaly_score: float
    current: bool = False


class ScanRequest(BaseModel):
    code: str = Field(min_length=1, max_length=2_000_000)
    language: Language = "python"
    room_id: str | None = Field(default=None, max_length=40)


class Finding(BaseModel):
    title: str
    category: str
    severity: str
    confidence: str
    line: int
    column: int = 0
    description: str
    remediation: str = ""
    cwe: str | None = None
    source: str
    evidence: str | None = None


class ScanOut(BaseModel):
    id: str
    created_at: datetime
    language: str
    risk_score: int
    highest_severity: str
    findings_count: int
    findings: list[Finding]
    code_sha256: str
    code_bytes: int
    room_id: str | None = None


class ScanSummary(BaseModel):
    id: str
    created_at: datetime
    language: str
    risk_score: int
    highest_severity: str
    findings_count: int
    code_sha256: str


class RoomCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    language: Language = "python"


class RoomCodeUpdate(BaseModel):
    code: str = Field(max_length=200_000)
    language: Language | None = None


class RoomOut(BaseModel):
    id: str
    name: str
    owner_id: str
    language: str
    created_at: datetime
    updated_at: datetime
    members: int
    code: str


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    severity: str
    title: str
    message: str
    created_at: datetime
    acknowledged: bool


class DashboardStats(BaseModel):
    active_sessions: int
    total_users: int
    scans_24h: int
    findings_24h: int
    critical_findings_24h: int
    avg_risk: float
    verified_sessions: int
    high_risk_sessions: int
    alerts_open: int


class ActivityPoint(BaseModel):
    t: str
    scans: int
    alerts: int


class DashboardOut(BaseModel):
    stats: DashboardStats
    sessions: list[SessionOut]
    alerts: list[AlertOut]
    recent_scans: list[ScanSummary]
    risk_distribution: dict[str, int]
    activity: list[ActivityPoint]
    anomaly_engine: str


class Page(BaseModel):
    items: list
    total: int
    limit: int
    offset: int
