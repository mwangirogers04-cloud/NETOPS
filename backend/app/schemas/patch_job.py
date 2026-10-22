from datetime import datetime
from pydantic import BaseModel, ConfigDict


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
    scheduled_at: datetime | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    is_local: bool = False
    working_hours_info: dict | None = None
