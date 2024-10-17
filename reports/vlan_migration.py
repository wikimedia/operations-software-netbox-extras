"""Report to keep track on migration away from row wide vlans."""

from re import subn

from collections import defaultdict
from datetime import datetime, timedelta

from dcim.models import Device
from ipam.models import Prefix

from extras.scripts import Script

LEGACY_VLANS = (
    "private1-a-codfw",
    "private1-b-codfw",
    "private1-c-codfw",
    "private1-d-codfw",
)


class VlanMigration(Script):
    """Show baremetal hosts on legacy vlans."""

    class Meta:
        name = "Legacy vlans migration"
        description = "Report to keep track on migration away from row wide vlans."

    description = __doc__

    def test_summary(self) -> None:
        """Group hosts by types (prefix)"""
        legacy_prefixes = []
        for prefix in Prefix.objects.filter(vlan__name__in=LEGACY_VLANS):
            legacy_prefixes.append(prefix)

        five_years_ago = datetime.now() - timedelta(days=5 * 365)
        total_device_count = 0
        devices_groups: dict = defaultdict(list)
        for device in Device.objects.filter(
            role__slug="server",
            status="active",
            site__slug__in=["codfw"],
            primary_ip4__isnull=False,
            custom_field_data__purchase_date__gte=five_years_ago,
        ):
            if any(
                device.primary_ip4.address in prefix.prefix
                for prefix in legacy_prefixes
            ):
                total_device_count += 1
                group, sub_count = subn(r"\d{4}", "", device.name)
                if sub_count:
                    devices_groups[group].append(device)

        devices_groups_sorted = dict(
            sorted(devices_groups.items(), key=lambda item: len(item[1]), reverse=True)
        )

        self.log_warning(
            f"{total_device_count} baremetal servers still on the legacy vlans"
        )
        for group, devices in devices_groups_sorted.items():
            names = ", ".join(
                [
                    device.name
                    for device in devices_groups[group][0:min(3, len(devices_groups[group]))]
                ]
            )
            self.log_info(
                f"{group}*: {len(devices)} servers ({names}...)",
                devices_groups[group][-1],
            )
