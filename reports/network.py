"""Report on various network related errors."""
import re

from collections import defaultdict

from dcim.choices import DeviceStatusChoices
from dcim.constants import VIRTUAL_IFACE_TYPES
from dcim.models import Device, Interface

from ipam.constants import IPADDRESS_ROLES_NONUNIQUE
from ipam.models import IPAddress

from extras.reports import Report

from django.db.models import Count

EXCLUDE_STATUSES = (
    DeviceStatusChoices.STATUS_DECOMMISSIONING,
    DeviceStatusChoices.STATUS_INVENTORY,
    DeviceStatusChoices.STATUS_OFFLINE,
    DeviceStatusChoices.STATUS_PLANNED,
)
SWITCHES_ROLES = ("asw", "msw", "cloudsw")
NETWORK_ROLES = ("asw", "cr", "mr", "pfw", "cloudsw")
ACCESS_INTERFACES_PREFIX = ("et-", "xe-", "ge-")
NO_V6_DEVICE_NAME_PREFIXES = (
    "clouddb",
    "db",
    "dbprov",
    "dbproxy",
    "dbstore",
    "dumpsdata",
    "es",
    "ganeti",
    "graphite",
    "maps",
    "mc",
    "mc-gp",
    "ms-be",
    "mw",
    "mwlog",
    "ores",
    "parse",
    "pc",
    "restbase",
    "restbase-dev",
    "sessionstore",
    "snapshot",
    "thanos-fe",
    "thumbor",
    "wdqs",
    "wtp",
)
NO_V6_DEVICE_NAMES = ("scandium",)


class Network(Report):
    """Report on various network-related errors."""

    description = __doc__

    def test_duplicate_interface(self):
        """Report duplicated interfaces on switches (and switch stack).

        Juniper only.
        For example if xe-2/0/18 and ge-2/0/18 are present, or if xe-2/0/18 exists twice on 2 different VC members.
        """
        seen_interfaces = defaultdict(set)
        for interface in Interface.objects.filter(
            device__device_role__slug__in=SWITCHES_ROLES,
            device__device_type__manufacturer__slug="juniper",
        ).exclude(device__status__in=EXCLUDE_STATUSES):
            # Only care about access interfaces
            if not str(interface.name).startswith(ACCESS_INTERFACES_PREFIX):
                continue
            # If the interface is on a VC device, check that the position match the interface name
            if interface.device.vc_position:
                interface_fpc = f"-{interface.device.vc_position}/"
                if interface_fpc not in interface.name:
                    self.log_failure(
                        interface,
                        (
                            f"Interface doesn't match its switch member: {interface.device.vc_position} ",
                            f"on {interface.device}",
                        ),
                    )
                    continue
            # If the interface is on a standalone switch, make sure the interface starts with -0/
            else:
                if "-0/" not in interface.name:
                    self.log_failure(
                        interface,
                        f"Interface on a non-VC should start with -0/ on {interface.device}",
                    )
                    continue
            # Make sure we don't have two types on interfaces with the same ID (number)
            if interface.name.split("-")[1] in seen_interfaces[interface.device.name]:
                self.log_failure(
                    interface,
                    f"Duplicated interface with different prefix (eg. xe- & ge-) on {interface.device}",
                )
                continue
            seen_interfaces[interface.device.name].add(interface.name.split("-")[1])

    def test_enabled_not_connected(self):
        """No interface on a network device should be enabled but not connected.

        Exception being management switches as we don't document them in core sites.
        """
        for interface in (
            Interface.objects.filter(device__device_role__slug__in=NETWORK_ROLES)
            .exclude(device__status__in=EXCLUDE_STATUSES)
            .exclude(cable__isnull=False)
            .exclude(type__in=VIRTUAL_IFACE_TYPES)
            .exclude(mgmt_only=True)
            .exclude(enabled=False)
        ):
            # Warning only for interfaces with "no-mon" in the description
            if interface.description and "no-mon" in interface.description:
                self.log_warning(
                    interface,
                    (
                        "Interface enabled but not connected on {} (description: {})".format(
                            interface.device, interface.description
                        )
                    ),
                )
                continue
            self.log_failure(
                interface, f"Interface enabled but not connected on {interface.device}"
            )

    def test_primary_ipv6(self):
        """Report servers that either have a missing primary_ip6 or have a primary_ip6 without a DNS name set.

        To help with T253173.
        """
        success = 0
        # Exclude fr-tech as long as they're v4 only
        for device in Device.objects.filter(
            device_role__slug="server", tenant__isnull=True
        ).exclude(status__in=EXCLUDE_STATUSES):
            if not device.primary_ip6:
                self.log_failure(device, "Missing primary IPv6")
                continue
            else:
                if device.name in NO_V6_DEVICE_NAMES or any(
                    re.match(rf"{name}[1-9]", device.name)
                    for name in NO_V6_DEVICE_NAME_PREFIXES
                ):
                    if device.primary_ip6.dns_name:
                        self.log_warning(
                            device,
                            "Primary IPv6 has DNS name on a cluster that is listed as not supporting IPv6",
                        )
                        continue
                else:
                    if not device.primary_ip6.dns_name:
                        self.log_failure(device, "Primary IPv6 missing DNS name")
                        continue
            success += 1
        self.log_success(None, f"{success} devices with operationnal primary IPv6")

    def test_duplicate_ip_netmask(self):
        """Report to check for duplicate IPs with different netmasks.

        When an IP is marked as VIP, Netbox allows to create it duplicated with different netmasks like 10.0.0.0/32 and
        10.0.0.0/27. We don't allow this, by always setting a netmask of /32 for all VIPs and not the subnet netmask as
        Netbox does by default.

        See also T273248#6791839
        """
        success = 0
        seen_ipaddress = defaultdict(set)
        # Iterate over all the VIPs, split the IP from mask, if duplicate, check that they match
        for ipaddress in IPAddress.objects.filter(role__in=IPADDRESS_ROLES_NONUNIQUE):
            seen_ipaddress[ipaddress.address.ip].add(ipaddress.address.prefixlen)
            if len(seen_ipaddress[ipaddress.address.ip]) > 1:
                self.log_failure(
                    ipaddress, "Multiple VIPs with different prefix length"
                )
            else:
                success += 1
        self.log_success(None, f"{success} correctly masked VIPs")

    def test_primary_ip_dns_match(self):
        """Check that primary IPv4/IPv6 DNS names match.

        If a device have both a primary IPv4 and IPv6 with DNS names, check that they match.  Also, check that the
        primary IPs DNS names match the hostname.
        """
        success = 0
        for device in Device.objects.filter(
            device_role__slug="server", tenant__isnull=True
        ).exclude(status__in=EXCLUDE_STATUSES):
            if not device.primary_ip4 or not device.primary_ip4.dns_name:
                self.log_failure(device, "Device with no primary IPv4 or DNS name")
                continue
            if not str(device.primary_ip4.dns_name).startswith(device.name + "."):
                self.log_failure(
                    device,
                    "Primary IPv4 DNS ({device.primary_ip4.dns_name}) doesn't start with the hostname",
                )

            if not device.primary_ip4 or not device.primary_ip6:
                continue
            if not device.primary_ip4.dns_name or not device.primary_ip6.dns_name:
                continue
            if device.primary_ip4.dns_name != device.primary_ip6.dns_name:
                self.log_failure(
                    device,
                    "Primary IPv4 and IPv6 DNS name mismatch ({} vs. {})".format(
                        device.primary_ip4.dns_name, device.primary_ip6.dns_name
                    ),
                )
                continue
            success += 1
        self.log_success(None, f"{success} devices with matching primary IPv4 & IPv6")

    def test_mgmt_dns_hostname(self):
        """No interface on a network device should be enabled but not connected.

        Exception being management switches as we don't document them in core sites.
        """
        success = 0
        for ipaddress in IPAddress.objects.filter(
            interface__name="mgmt", dns_name__isnull=False
        ).exclude(dns_name=""):
            tenant = ""
            if (
                ipaddress.assigned_object.device.tenant
                and ipaddress.assigned_object.device.tenant.slug == "fr-tech"
            ):
                tenant = "frack."
            expected_fqdn = "{}.mgmt.{}{}.wmnet".format(
                ipaddress.assigned_object.device.name,
                tenant,
                ipaddress.assigned_object.device.site.slug,
            )
            if not ipaddress.dns_name == expected_fqdn:
                self.log_failure(
                    ipaddress.assigned_object.device,
                    f"Invalid management interface DNS ({ipaddress.dns_name} != {expected_fqdn})",
                )
            else:
                success += 1
        self.log_success(None, f"{success} correct mgmt DNS names")

    def test_matching_vlan(self):
        """Check IPs are assigned to server ports match the connected Vlan.

        Every IP address bound to a host interface should come from the correct
        subnet, matching the Vlan the equivalent switch port is bound to.
        """
        success = 0
        for interface in (
            Interface.objects.filter(device__device_role__slug="server")
            .exclude(cable__isnull=True)
            .annotate(Count("ip_addresses"))
            .filter(ip_addresses__count__gte=1)
            .select_related("_path")  # This is the field name for connected_endpoint
            .prefetch_related(
                "ip_addresses", "connected_endpoint__untagged_vlan__prefixes"
            )
        ):
            if interface.connected_endpoint.device.device_role.slug not in (
                "asw",
                "cloudsw",
            ):
                continue

            prefixes = defaultdict(list)
            for prefix in interface.connected_endpoint.untagged_vlan.prefixes.all():
                prefixes[prefix.family].append(prefix)

            ips = defaultdict(list)
            for ip in interface.ip_addresses.all():
                ips[ip.family].append(ip)

            for family in (4, 6):
                family_prefixes = prefixes[family]
                if not family_prefixes:
                    self.log_warning(
                        interface.connected_endpoint.untagged_vlan,
                        f"Vlan has no IPv{family} prefix assigned.",
                    )
                    continue

                if len(family_prefixes) > 1:
                    self.log_failure(
                        interface.connected_endpoint.untagged_vlan,
                        f"Vlan has more than one IPv{family} prefix assigned: {family_prefixes}",
                    )

                prefix = family_prefixes[0]
                for ip in ips[family]:
                    if (
                        ip.address.network != prefix.prefix.network
                        or ip.address.prefixlen != prefix.prefix.prefixlen
                    ):
                        self.log_failure(
                            interface.device,
                            f"{ip.address} does not match connected Vlan "
                            f"{interface.connected_endpoint.untagged_vlan}",
                        )
                    else:
                        success += 1

        if success > 0:
            self.log_success(
                None,
                f"{success} server IP allocations matched attached switch port Vlan.",
            )

    def test_port_block_consistency(self):
        """Validate that port types within each block of 4 are consistent for QFX5120 series.

        Trident 3 based devices like the QFX5120 have a constraint that port speeds (1/10/25Gb)
        must be consistent within each block of 4 (i.e. 0-3, 4-7, 8-11 etc).  This check validates
        the data in Netbox conforms to this constraint.

        Only the SFP28 slots 0-47 are considered as the constraint does not apply to QSFP28 ports.
        """
        success = 0
        for device in Device.objects.filter(device_type__slug="qfx5120-48y-8c"):
            port_blocks = {}
            device_failed = False
            for interface in device.interfaces.exclude(
                type__in=("virtual", "lag")
            ).exclude(mgmt_only=True).exclude(enabled=False):
                try:
                    port = int(interface.name.split(":")[0].split("/")[-1])
                except ValueError:
                    self.log_failure(
                        interface,
                        f"[{device.site.slug}] Invalid interface name on Juniper QFX5120 "
                        f"device '{device.name}'",
                    )
                    continue
                if port >= 48:
                    continue

                block = port - (port % 4)
                if block not in port_blocks:
                    port_blocks[block] = interface.type
                elif port_blocks[block] != interface.type:
                    block_members = (
                        ", ".join(str(x) for x in range(block, 3)) + f" and {block+4}"
                    )
                    self.log_failure(
                        interface,
                        f"[{device.site.slug}] Interface type '{interface.type}' does not match "
                        f"'{port_blocks[block]}' set on other(s) in same block on {device.name}. "
                        f"Ports {block_members} need to be same type.",
                    )
                    device_failed = True

            if not device_failed:
                success += 1

        if success > 0:
            self.log_success(
                None,
                f"{success} QFX5120 devices have no port speed inconsistencies within blocks of 4.",
            )
