"""Validator class for the Device model."""

import re
import datetime

from dcim.choices import DeviceStatusChoices
from dcim.models import Device
from extras.validators import CustomValidator

ROLES_OK_NO_ASSET_TAG = ("patch-panel",)
ROLES_OK_NO_SERIAL = ("cablemgmt", "storagebin", "optical-device", "patch-panel")
STATUS_DECOM = (
    DeviceStatusChoices.STATUS_DECOMMISSIONING,
    DeviceStatusChoices.STATUS_OFFLINE,
)
INVALID_ACTIVE_NAMES = ["future", "spare"]

ASSET_TAG_RE = re.compile(
    r"WMF\d{4,}"
)  # Update the error message if you edit the regex
TICKET_RE = re.compile(r"RT #\d{2,}|T\d{5,}")


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance):
        """Mandatory entry point"""
        # Name
        if instance.name != instance.name.lower():
            self.fail("Invalid name (must be lowercase)")
        if instance.status == DeviceStatusChoices.STATUS_ACTIVE and any(
            x in instance.name for x in INVALID_ACTIVE_NAMES
        ):
            self.fail(
                f"Invalid name (active device name must not contain {INVALID_ACTIVE_NAMES})"
            )
        if "." in instance.name:
            self.fail("Invalid name (must not contain a dot)")
        # TODO valid hostname (not FQDN, so no dots) regex
        # in addition if a 4 digit number is present the first digit
        # must match the DC's digit prefix rule (eqiad => 1, etc.)

        # asset_tag
        if instance.device_role.slug not in ROLES_OK_NO_ASSET_TAG:
            if instance.asset_tag is None:
                self.fail("Missing asset tag")
            if not ASSET_TAG_RE.fullmatch(instance.asset_tag):
                self.fail("Invalid asset tag (must be WMF then 4 or more digits)")

        # purchase_date
        purchase_date = instance.cf["purchase_date"]
        if purchase_date is None:
            self.fail("Missing purchase date")
        if (
            datetime.date.fromisoformat(str(purchase_date))
            > datetime.datetime.today().date()
        ):
            self.fail("Invalid purchase date (must not be in the future")

        # ticket
        ticket = str(instance.cf["ticket"])
        if ticket is None:
            self.fail("Missing procurement ticket")
        if not TICKET_RE.fullmatch(ticket):
            self.fail(
                "Invalid procurement ticket (must start with RT or T then digits)"
            )

        # serial
        if (instance.device_role.slug not in ROLES_OK_NO_SERIAL) and (
            instance.status not in STATUS_DECOM
        ):
            if instance.serial is None or instance.serial == "":
                self.fail("Missing serial number")
            device_same_serial = Device.objects.filter(serial=instance.serial).first()
            if device_same_serial and device_same_serial != instance:
                self.fail(f"Duplicate serial number with {device_same_serial}")

        # status
        if (
            instance.device_role.slug == "server"
            and instance.status == DeviceStatusChoices.STATUS_STAGED
        ):
            self.fail("Invalid role/status (servers must not use STAGED)")

        # Rack
        if instance.status == DeviceStatusChoices.STATUS_OFFLINE and instance.rack:
            self.fail(
                "Invalid rack/status (OFFLINE devices most not have rack defined)"
            )
        if instance.status == DeviceStatusChoices.STATUS_ACTIVE and not instance.rack:
            self.fail("Invalid rack/status (ACTIVE devices must have rack defined)")
        if (
            instance.device_type.u_height >= 1
            and instance.rack
            and not instance.position
        ):
            self.fail(
                "Invalid rack/position (device with U height and rack must have position)"
            )
