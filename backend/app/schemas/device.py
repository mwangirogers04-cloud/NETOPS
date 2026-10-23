from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, computed_field, field_validator


class DeviceCreate(BaseModel):
    mac_address: str
    ip_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    switch_name: str | None = None
    switch_port: str | None = None
    network_interface: str | None = None
    vlan_id: int | None = None
    ip_assignment: str = "dhcp"
    notes: str | None = None

    @field_validator("network_interface", mode="before")
    @classmethod
    def _clean_network_interface(cls, v: Any) -> str | None:
        return v if isinstance(v, str) else None

    @field_validator("ip_assignment", mode="before")
    @classmethod
    def _clean_ip_assignment(cls, v: Any) -> str:
        return v if isinstance(v, str) and v.strip() else "dhcp"


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
        if self.enforcement_status == "isolated":
            return "Device is explicitly isolated from the network (VLAN 90)"

        if self.approval_status == "pending":
            return "Pending administrator approval"

        if self.approval_status == "rejected":
            return "Rejected by administrator"

        if self.classification_status == "review_required":
            return "Classification mismatch requires manual review"

        known_types = {
            "ip_phone",
            "phone",
            "voip",
            "computer",
            "cctv",
            "printer",
            "server",
            "servers",
            "access_point",
            "ap",
            "wap",
            "wifi_ap",
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


class DeviceIpAssignmentUpdate(BaseModel):
    ip_assignment: str


class BulkDeleteRequest(BaseModel):
    device_ids: list[int]
