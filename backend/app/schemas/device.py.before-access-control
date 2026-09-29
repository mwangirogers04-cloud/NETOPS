from datetime import datetime

from pydantic import BaseModel, ConfigDict, computed_field


class DeviceCreate(BaseModel):
    mac_address: str
    ip_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    switch_name: str | None = None
    switch_port: str | None = None
    vlan_id: int | None = None
    notes: str | None = None


class DeviceResponse(DeviceCreate):
    id: int
    status: str
    approval_status: str
    classification_status: str
    enforcement_status: str

    access_decision: str | None = None

    first_seen: datetime
    last_seen: datetime

    model_config = ConfigDict(
        from_attributes=True
    )

    @computed_field
    @property
    def access_reason(self) -> str:
        if self.approval_status == "pending":
            return "Pending administrator approval"

        if self.approval_status == "rejected":
            return "Rejected by administrator"

        if self.classification_status == "review_required":
            return "Classification mismatch requires manual review"

        if not self.device_type:
            return "Unknown device type"

        known_types = {
            "computer",
            "cctv",
            "printer",
        }

        if self.device_type.lower().strip() not in known_types:
            return "Unrecognized device type"

        if self.approval_status == "approved":
            return "Approved recognized device"

        return "Network access restricted"


class DeviceTypeUpdate(BaseModel):
    device_type: str
