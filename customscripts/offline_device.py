from _common import format_logs

from dcim.models import Device
from extras.scripts import Script, StringVar


class OfflineDevice(Script):
    class Meta:
        name = "Offline a device with extra actions"
        description = (
            "Set the device status to Offline (unracked), unset its position and delete all interfaces "
            "and related IP addresses."
        )
        commit_default = False  # noqa: unused-variable

    devices = StringVar(
        label="Device name(s)",
        description="Device to be offlined, space separated if more than one",
    )

    def run(self, data, commit):  # noqa: unused-argument
        """Offline the device."""
        try:
            self._run(data)
        except Exception as e:  # noqa: broad-exception-caught TODO: fix after upgrade
            self.log_failure(f"Failed to offline device(s) {data['device_name']}: {e}")

        return format_logs(self.messages)

    def _run(self, data):
        """Actually run the script."""
        devices = Device.objects.filter(name__in=data["devices"].split())
        self.log_info(f"Found {len(devices)} Netbox devices")

        for device in devices:
            self._run_device(device)

    def _run_device(self, device):
        """Run the script for one device."""
        if device.status != "decommissioning":
            self.log_failure(
                (
                    f"Device {device} is in {device.status} status, only decommissioned devices "
                    "can be offlined. Skipping device."
                )
            )
            return

        self.log_info(f"Setting device {device} status to Offline and unset rack/unit position")
        device.status = "offline"
        device.rack = None
        device.position = None
        device.face = ""  # noqa: unused-variable
        device.primary_ip4 = None
        device.primary_ip6 = None
        device.save()  # Avoid any race condition with DNS generations scripts

        for interface in device.interfaces.all():
            for address in interface.ip_addresses.all():
                self.log_info(
                    (
                        f"Deleting address {address} with DNS {address.dns_name} "
                        f"on interface {interface} for device {device}"
                    )
                )
                address.delete()

            self.log_info(f"Deleting interface {interface} on device {device}")
            interface.delete()

        device.save()
        self.log_success(f"Successfully offlined device {device}")
