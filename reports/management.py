"""Check certain kinds of devices for the presence of a console port."""

from dcim.choices import DeviceStatusChoices
from dcim.models import Device
from extras.reports import Report

# These are the device type slugs we care about.
# Currently we alert on Core Routers and Core/Access Switch
DEVICE_ROLES = ("cr", "asw", "mr", "pfw", "cloudsw")

# These are points of presence slugs that we ignore for the purposes of this report.
# Network POPs don't have a console server
EXCLUDED_SITES = ("eqord", "eqdfw")


class ManagementConsole(Report):
    """All checks related to management/console."""

    description = __doc__

    def test_management_console(self):
        """Check certain kinds of devices for the presence of a console port and cable."""
        successcount = 0
        for device in (
            Device.objects.exclude(
                status__in=(
                    DeviceStatusChoices.STATUS_INVENTORY,
                    DeviceStatusChoices.STATUS_OFFLINE,
                    DeviceStatusChoices.STATUS_PLANNED,
                    DeviceStatusChoices.STATUS_DECOMMISSIONING,
                )
            )
            .filter(role__slug__in=DEVICE_ROLES)
            .exclude(site__slug__in=EXCLUDED_SITES)
        ):
            ports = device.consoleports.all()

            if not ports:
                self.log_failure(device, "missing console port")
                continue

            for port in ports:
                if port.cable:
                    successcount += 1
                    break
            else:
                self.log_failure(device, "missing connected console port")
        self.log_success(None, f"{successcount} devices with connected ports")
