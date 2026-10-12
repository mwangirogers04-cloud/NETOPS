import time

from ..database import SessionLocal
from ..models.device import Device
from .network_enforcement import enforce_device_access

def enforce_all_devices_once(db=None):
    """
    Run one enforcement cycle for all known devices.

    If a database session is supplied, reuse it.
    Otherwise, create and manage a temporary session.

    NETOPS is currently operating in simulation mode.
    No real firewall, switch, or VLAN changes are performed.
    """

    owns_session = db is None

    if owns_session:
        db = SessionLocal()

    try:
        devices = (
            db.query(Device)
            .order_by(Device.id)
            .all()
        )

        results = []

        for device in devices:
            result = enforce_device_access(
                device,
                db,
            )

            results.append(result)

        if owns_session:
            db.commit()

        return results

    except Exception:
        if owns_session:
            db.rollback()
        raise

    finally:
        if owns_session:
            db.close()


def monitor_enforcement(
    interval: int = 30,
):
    """
    Continuously evaluate device access schedules.

    The default interval is 30 seconds.
    """

    print("NETOPS enforcement monitor started")
    print(
        f"Enforcement interval: "
        f"{interval} seconds"
    )

    while True:
        try:
            results = enforce_all_devices_once()

            allowed = sum(
                1
                for result in results
                if result["enforcement_status"] == "allowed"
            )

            quarantined = sum(
                1
                for result in results
                if result["enforcement_status"]
                == "quarantined"
            )

            print("")
            print("[ENFORCEMENT] Cycle complete")
            print(
                f"[ENFORCEMENT] Devices checked: "
                f"{len(results)}"
            )
            print(
                f"[ENFORCEMENT] Allowed: "
                f"{allowed}"
            )
            print(
                f"[ENFORCEMENT] Quarantined: "
                f"{quarantined}"
            )

        except Exception as error:
            print(
                f"[ERROR] Enforcement monitor error: "
                f"{error}"
            )

        time.sleep(interval)


if __name__ == "__main__":
    monitor_enforcement(
        interval=30,
    )
