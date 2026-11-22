import json
from datetime import datetime
from pydantic import BaseModel, ConfigDict, field_validator


class CreatePatchJobRequest(BaseModel):
    hostname: str
    ip_address: str | None = None
    mac_address: str | None = None
    machine_id: str | None = None
    device_id: int | None = None
    action: str = "INSTALL_ALL_UPDATES"
    initiated_by: str = "console"
    scheduled_at: datetime | None = None
    schedule_mode: str | None = None  # "now", "scheduled", "off_hours"
    respect_working_hours: bool = False
    force_working_hours: bool = False
    remote_protocol: str | None = None  # "auto", "winrm", "ssh", "agent"
    remote_username: str | None = None
    remote_password: str | None = None
    remote_port: int | None = None
    remote_auth_type: str | None = "password"
    remote_ssh_key: str | None = None


class UpdatePolicyUpdateRequest(BaseModel):
    default_working_start: str = "08:00"
    default_working_end: str = "17:00"
    default_working_days: str = "weekdays"
    auto_off_hours_enabled: bool = False
    block_working_hours_schedule: bool = True
    post_work_delay_minutes: int = 5


class UpdatePolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    default_working_start: str
    default_working_end: str
    default_working_days: str
    auto_off_hours_enabled: bool
    block_working_hours_schedule: bool
    post_work_delay_minutes: int
    updated_at: datetime


class WorkingHoursCheckRequest(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    device_id: int | None = None
    scheduled_at: datetime | None = None


class UpdateJobStatusRequest(BaseModel):
    status: str
    progress_percent: int | None = None
    log_output: str | None = None
    error_message: str | None = None
    installed_updates: list[dict] | str | None = None


class PatchJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_id: int | None = None
    hostname: str
    ip_address: str | None = None
    mac_address: str | None = None
    machine_id: str | None = None
    operating_system: str | None = None
    action: str
    status: str
    progress_percent: int
    initiated_by: str
    log_output: str | None = None
    error_message: str | None = None
    installed_updates: list[dict] | None = None
    scheduled_at: datetime | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    is_local: bool = False
    working_hours_info: dict | None = None

    @field_validator("installed_updates", mode="before")
    @classmethod
    def parse_installed_updates(cls, v):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return None
        return v


class TestRemoteConnectionRequest(BaseModel):
    ip_address: str
    protocol: str = "auto"  # "auto", "winrm", "ssh"
    username: str
    password: str | None = None
    port: int | None = None
    ssh_key: str | None = None
    save_credentials: bool = False
    device_id: int | None = None
    hostname: str | None = None
    mac_address: str | None = None


class TestRemoteConnectionResponse(BaseModel):
    connected: bool
    protocol: str
    message: str
    os_info: str | None = None


class RebootEndpointRequest(BaseModel):
    hostname: str
    ip_address: str | None = None
    mac_address: str | None = None
    device_id: int | None = None
    delay_seconds: int = 5
    reason: str = "System update finalization reboot"
    auto_reboot_after_updates: bool = False


class RebootEndpointResponse(BaseModel):
    status: str
    message: str
    hostname: str
    ip_address: str | None = None
    action: str = "REBOOT_MACHINE"
    dispatched_at: datetime
    initiated_by: str

