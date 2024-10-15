"""Report to keep track on migration away from row wide vlans."""

from re import subn

from collections import defaultdict

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
            self.log_info("Legacy prefix", prefix)

        total_device_count = 0
        devices_groups: dict = defaultdict(int)
        for device in Device.objects.filter(
            role__slug="server",
            status="active",
            site__slug__in=["codfw"],
            primary_ip4__isnull=False,
        ):
            if any(
                device.primary_ip4.address in prefix.prefix
                for prefix in legacy_prefixes
            ):
                total_device_count += 1
                group, sub_count = subn(r"\d{4}", "", device.name)
                if sub_count:
                    devices_groups[group] += 1

        devices_groups_sorted = dict(
            sorted(devices_groups.items(), key=lambda item: item[1], reverse=True)
        )

        self.log_warning(
            f"{total_device_count} baremetal servers still on the legacy vlans"
        )
        for group, count in devices_groups_sorted.items():
            self.log_info(f"{group}*: {count} servers")
