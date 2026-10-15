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
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    is_local: bool = False
