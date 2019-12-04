"""
Several integrity/coherence checks against the data.
"""

import datetime
import re

from dcim.constants import (
    DEVICE_STATUS_ACTIVE,
    DEVICE_STATUS_DECOMMISSIONING,
    DEVICE_STATUS_OFFLINE,
    DEVICE_STATUS_PLANNED,
    DEVICE_STATUS_INVENTORY,
)
from dcim.models import Device
from extras.reports import Report
from extras.models import CustomFieldValue

from django.db.models import Count, Prefetch


SITE_BLACKLIST = ()
DEVICE_ROLE_BLACKLIST = ("cablemgmt", "storagebin", "optical-device")
ASSET_TAG_RE = re.compile(r"WMF\d{4}")
TICKET_RE = re.compile(r"RT #\d{2,}|T\d{5,}")


def cf(device, field):
    """Get the value for the specified custom field name.

    This, combined with the a prefetch_related() results into much more
    efficient access of custom fields and their values. See:
    https://github.com/digitalocean/netbox/issues/3185

    Be warned that this treats empty values as non-existing fields.
    """
    for cfv in device.custom_field_values.all():
        if cfv.field.name == field:
            return cfv.value
    return None


# monkey-patch the Device model for easy access to our custom cf() function
Device.mpcf = cf


def _get_devices_query(cf=False):
    devices = Device.objects.exclude(site__slug__in=SITE_BLACKLIST)
    if cf:
        devices = devices.prefetch_related(
            Prefetch("custom_field_values", queryset=CustomFieldValue.objects.select_related("field"))
        )

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
        for device in _get_devices_query(cf=True):
            purchase_date = device.mpcf("purchase_date")
            if purchase_date is None:
                self.log_failure(device, "missing purchase date")
            elif purchase_date > datetime.datetime.today().date():
                self.log_failure(device, "purchase date is in the future")
            else:
                success_count += 1
        self.log_success(None, "{} present purchase dates".format(success_count))

    def test_duplicate_serials(self):
        """Test that all serial numbers are unique."""
        dups = (
            _get_devices_query()
            .values("serial")
            .exclude(device_role__slug__in=DEVICE_ROLE_BLACKLIST)
            .exclude(status__in=(DEVICE_STATUS_DECOMMISSIONING, DEVICE_STATUS_OFFLINE))
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
                .exclude(status__in=(DEVICE_STATUS_DECOMMISSIONING, DEVICE_STATUS_OFFLINE))
                .filter(serial__in=list(dups))
                .order_by("serial")
            ):
                self.log_failure(device, "duplicate serial: {}".format(device.serial))
        else:
            self.log_success(None, "No duplicate serials found")

    def test_serials(self):
        """Determine if all serials are non-null."""
        success_count = 0
        for device in (
            _get_devices_query()
            .exclude(status__in=(DEVICE_STATUS_DECOMMISSIONING, DEVICE_STATUS_OFFLINE))
            .exclude(device_role__slug__in=DEVICE_ROLE_BLACKLIST)
        ):
            if device.serial is None or device.serial == "":
                self.log_failure(device, "missing serial")
            else:
                success_count += 1
        self.log_success(None, "{} present serials".format(success_count))

    def test_ticket(self):
        """Determine if the procurement ticket matches the expected format."""
        success_count = 0
        for device in _get_devices_query(cf=True):
            ticket = str(device.mpcf("ticket"))
            if TICKET_RE.fullmatch(ticket):
                success_count += 1
            elif device.mpcf("ticket") is None:
                self.log_failure(device, "missing procurement ticket")
            else:
                self.log_failure(device, "malformed procurement ticket: {}".format(ticket))

        self.log_success(None, "{} correctly formatted procurement tickets".format(success_count))

    def test_offline_rack(self):
        """Determine if offline boxes are (erroneously) assigned a rack."""
        devices = _get_devices_query().filter(status=DEVICE_STATUS_OFFLINE).exclude(rack=None)
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
            .exclude(status__in=(DEVICE_STATUS_OFFLINE, DEVICE_STATUS_PLANNED, DEVICE_STATUS_INVENTORY))
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
                if port.connection_status:
                    msgs.append(port.name)
                    good = False
            if not good:
                self.log_failure(device, " ".join(msgs))

    def test_device_name(self):
        """Device names should be lower case."""
        success = 0
        warnings = []
        for device in _get_devices_query():
            if device.name.lower() != device.name:
                if device.status == DEVICE_STATUS_ACTIVE:
                    self.log_failure(device, "malformed device name for active device")
                else:
                    warnings.append(device)
            else:
                success += 1

        [self.log_warning(x, "malformed device name for inactive device") for x in warnings]
        self.log_success(None, "{} correctly formatted device names".format(success))
