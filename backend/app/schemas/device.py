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
    internet_access_authorized: bool

    access_decision: str | None = None

    update_status: str | None = None
    pending_updates: int | None = None
    security_updates: int | None = None
    last_update_check: datetime | None = None
    operating_system: str | None = None
    os_version: str | None = None

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

        known_types = {
            "computer",
            "cctv",
            "printer",
        }

        if (
            not self.device_type
            or self.device_type.lower().strip() not in known_types
        ):
            return "Unknown or unrecognized device type"

        if not self.internet_access_authorized:
            return "Internet access has not been explicitly authorized"

        if self.enforcement_status != "allowed":
            return (
                "Internet access is currently quarantined "
                "by policy or schedule"
            )

        return "Approved recognized device with internet access allowed"


class DeviceTypeUpdate(BaseModel):
    device_type: str


class DeviceVlanUpdate(BaseModel):
    vlan_id: int
