"""
Several integrity/coherence checks against the data.
"""

import datetime
import re

from dcim.choices import DeviceStatusChoices
from dcim.models import Device, InventoryItem
from extras.reports import Report

from django.db.models import Count


SITE_BLOCKLIST = ('drmrs',)
DEVICE_ROLE_BLOCKLIST = ("cablemgmt", "storagebin", "optical-device")
ASSET_TAG_RE = re.compile(r"WMF\d{4}")
TICKET_RE = re.compile(r"RT #\d{2,}|T\d{5,}")
JUNIPER_INVENTORY_PART_EXCLUDES = [
    "EX4500-VC1-128G",
    "EX4500-LB",
    "EX-UM-2X4SFP",
]
JUNIPER_INVENTORY_DESC_RE = re.compile(r".*Purchase:\d{4}-\d{2}-\d{2},Task:(T\d{6}|RT #\d+).*")
INVALID_ACTIVE_NAMES = ['future', 'spare']


def _get_devices_query(cf=False):
    devices = Device.objects.exclude(site__slug__in=SITE_BLOCKLIST)
    return devices


class Coherence(Report):
    description = __doc__

    def test_malformed_asset_tags(self):
        """Test for missing asset tags and incorrectly formatted asset tags."""
        success_count = 0
        for device in _get_devices_query():
            if device.asset_tag is None:
                self.log_failure(device, "missing asset tag")
            elif not ASSET_TAG_RE.fullmatch(device.asset_tag):
                self.log_failure(device, "malformed asset tag: {}".format(device.asset_tag))
            else:
                success_count += 1
        self.log_success(None, "{} correctly formatted asset tags".format(success_count))

    def test_purchase_date(self):
        """Test that each device has a purchase date."""
        success_count = 0
        for device in _get_devices_query():
            purchase_date = device.cf["purchase_date"]
            if purchase_date is None:
                self.log_failure(device, "missing purchase date")
            elif datetime.date.fromisoformat(purchase_date) > datetime.datetime.today().date():
                self.log_failure(device, "purchase date is in the future")
            else:
                success_count += 1
        self.log_success(None, "{} present purchase dates".format(success_count))

    def test_duplicate_serials(self):
        """Test that all serial numbers are unique."""
        dups = (
            _get_devices_query()
            .values("serial")
            .exclude(device_role__slug__in=DEVICE_ROLE_BLOCKLIST)
            .exclude(status__in=(DeviceStatusChoices.STATUS_DECOMMISSIONING, DeviceStatusChoices.STATUS_OFFLINE))
            .exclude(serial="")
            .exclude(serial__isnull=True)
            .annotate(count=Count("pk"))
            .values_list("serial", flat=True)
            .order_by()
            .filter(count__gt=1)
        )

        if dups:
            for device in (
                _get_devices_query()
                .exclude(status__in=(DeviceStatusChoices.STATUS_DECOMMISSIONING, DeviceStatusChoices.STATUS_OFFLINE))
                .filter(serial__in=list(dups))
                .order_by("serial")
            ):
                self.log_failure(device, "duplicate serial: {}".format(device.serial))
        else:
            self.log_success(None, "No duplicate serials found")

    def test_serials(self):
        """Determine if all serial numbers are non-null."""
        success_count = 0
        for device in (
            _get_devices_query()
            .exclude(status__in=(DeviceStatusChoices.STATUS_DECOMMISSIONING, DeviceStatusChoices.STATUS_OFFLINE))
            .exclude(device_role__slug__in=DEVICE_ROLE_BLOCKLIST)
        ):
            if device.serial is None or device.serial == "":
                self.log_failure(device, "missing serial number")
            else:
                success_count += 1
        self.log_success(None, "{} present serial numbers".format(success_count))

    def test_ticket(self):
        """Determine if the procurement ticket matches the expected format."""
        success_count = 0
        for device in _get_devices_query(cf=True):
            ticket = str(device.cf["ticket"])
            if TICKET_RE.fullmatch(ticket):
                success_count += 1
            elif device.cf["ticket"] is None:
                self.log_failure(device, "missing procurement ticket")
            else:
                self.log_failure(device, "malformed procurement ticket: {}".format(ticket))

        self.log_success(None, "{} correctly formatted procurement tickets".format(success_count))

    def test_device_name(self):
        """Device names should be lower case."""
        success = 0
        warnings = []
        for device in _get_devices_query():
            if device.name.lower() != device.name:
                if device.status == DeviceStatusChoices.STATUS_ACTIVE:
                    self.log_failure(device, "malformed device name for active device")
                else:
                    warnings.append(device)
            elif (any(x in device.name for x in INVALID_ACTIVE_NAMES)
                  and device.status == DeviceStatusChoices.STATUS_ACTIVE):
                self.log_failure(device, "Future or spare in active device name")
            else:
                success += 1

        [self.log_warning(x, "malformed device name for inactive device") for x in warnings]
        self.log_success(None, "{} correctly formatted device names".format(success))

    def test_juniper_inventory_descs(self):
        """Juniper inventory items which are not power supplies should have a structured description."""
        success = 0
        for inv in (
            InventoryItem.objects.filter(manufacturer__slug='juniper')
            .exclude(name__startswith='Power Supply')
            .exclude(part_id__in=JUNIPER_INVENTORY_PART_EXCLUDES)
        ):
            if JUNIPER_INVENTORY_DESC_RE.match(inv.description):
                success += 1
            else:
                self.log_failure(inv, "malformed inventory description: {}".format(inv.description))
        self.log_success(None, "{} correctly formatted inventory descriptions".format(success))


class Rack(Report):
    description = "Several integrity/coherence checks against the rack related data."

    def test_offline_rack(self):
        """Determine if offline boxes are (erroneously) assigned a rack."""
        devices = _get_devices_query().filter(status=DeviceStatusChoices.STATUS_OFFLINE).exclude(rack=None)
        devices = devices.select_related("site", "rack")
        for device in devices:
            self.log_failure(
                device,
                "rack defined for status {status} device: {site}-{rack}".format(
                    status="Offline", site=device.site.slug, rack=device.rack.name
                ),
            )

    def test_online_rack(self):
        """Determine if online boxes are (erroneously) lacking a rack assignment."""
        for device in (
            _get_devices_query()
            .exclude(
                status__in=(
                    DeviceStatusChoices.STATUS_OFFLINE,
                    DeviceStatusChoices.STATUS_PLANNED,
                    DeviceStatusChoices.STATUS_INVENTORY,
                )
            )
            .filter(rack=None)
        ):
            self.log_failure(device, "no rack defined for status {} device".format(device.get_status_display()))

    def test_connected_unracked(self):
        """Determine if unracked boxes still have console connections marked as conneced."""
        for device in _get_devices_query().filter(rack=None):
            consoleports = device.consoleports.all()
            good = True
            msgs = ["connected console ports attached to unracked device {}:".format(device.name)]
            for port in consoleports:
                if port.cable:
                    msgs.append(port.name)
                    good = False
            if not good:
                self.log_failure(device, " ".join(msgs))

    def test_rack_noposition(self):
        """Report errors on devices that have no rack position."""
        for device in _get_devices_query().filter(
            device_type__u_height__gte=1, position__isnull=True, rack__isnull=False
        ):
            self.log_failure(device, "no position set for racked device with U height")
