"""
Report on various network related errors.

"""
import re

from collections import defaultdict

from dcim.choices import DeviceStatusChoices
from dcim.constants import VIRTUAL_IFACE_TYPES
from ipam.constants import IPADDRESS_ROLES_NONUNIQUE

from dcim.models import Device, Interface
from extras.reports import Report
from ipam.models import IPAddress, Prefix

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
    "cloudbackup",
    "cloudcephmon",
    "cloudcephosd",
    "clouddb",
    "cloudnet",
    "cloudvirt",
    "cloudvirt-wdqs",
    "db",
    "dbprov",
    "dbproxy",
    "dbstore",
    "dumpsdata",
    "es",
    "ganeti",
    "graphite",
    "kafka-logging",
    "logstash",
    "maps",
    "mc",
    "mc-gp",
    "ms-be",
    "mw",
    "mwlog",
    "ores",
    "parse",
    "pc",
    "rdb",
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
        for interface in (Interface.objects.filter(device__device_role__slug__in=SWITCHES_ROLES,
                                                   device__device_type__manufacturer__slug='juniper')
                                           .exclude(device__status__in=EXCLUDE_STATUSES)):
            # Only care about access interfaces
            if not str(interface.name).startswith(ACCESS_INTERFACES_PREFIX):
                continue
            # If the interface is on a VC device, check that the position match the interface name
            if interface.device.vc_position:
                interface_fpc = "-{}/".format(interface.device.vc_position)
                if interface_fpc not in interface.name:
                    self.log_failure(interface,
                                     "Interface doesn't match its switch member: {} on {}"
                                     .format(interface.device.vc_position, interface.device))
                    continue
            # If the interface is on a standalone switch, make sure the interface starts with -0/
            else:
                if "-0/" not in interface.name:
                    self.log_failure(interface,
                                     "Interface on a non-VC should start with -0/ on {}"
                                     .format(interface.device))
                    continue
            # Make sure we don't have two types on interfaces with the same ID (number)
            if interface.name.split('-')[1] in seen_interfaces[interface.device.name]:
                self.log_failure(interface, ("Duplicated interface with different prefix (eg. xe- & ge-) on {}"
                                             .format(interface.device)))
                continue
            else:
                seen_interfaces[interface.device.name].add(interface.name.split('-')[1])

    def test_enabled_not_connected(self):
        """No interface on a network device should be enabled but not connected.

        Exception being management switches as we don't document them in core sites.
        """
        for interface in (Interface.objects.filter(device__device_role__slug__in=NETWORK_ROLES)
                                           .exclude(device__status__in=EXCLUDE_STATUSES)
                                           .exclude(cable__isnull=False)
                                           .exclude(type__in=VIRTUAL_IFACE_TYPES)
                                           .exclude(mgmt_only=True)
                                           .exclude(enabled=False)):
            # Warning only for interfaces with "no-mon" in the description
            if interface.description and "no-mon" in interface.description:
                self.log_warning(interface, ("Interface enabled but not connected on {} (description: {})"
                                             .format(interface.device, interface.description)))
                continue
            self.log_failure(interface, "Interface enabled but not connected on {}".format(interface.device))

    def test_disabled_configured(self):
        """No interface on a network device should be disabled but with config data.

        Exception being interfaces with "no-mon" in the description.
        """

        attributes = ['description', 'lag', 'mtu', 'mode', 'mac_address', 'count_ipaddresses']
        for interface in (Interface.objects.filter(device__device_role__slug__in=NETWORK_ROLES)
                                           .exclude(device__status__in=EXCLUDE_STATUSES)
                                           .exclude(cable__isnull=False)
                                           .exclude(enabled=True)):
            no_mon = False
            # Warning only for interfaces with "no-mon" in the description
            if interface.description and "no-mon" in interface.description:
                no_mon = True

            for attribute in attributes:
                if getattr(interface, attribute):
                    if no_mon:
                        self.log_warning(interface, f"[no-mon] Interface disabled but "
                                                    f"{attribute} set on {interface.device}")
                    else:
                        self.log_failure(interface, f"Interface disabled but {attribute} set on {interface.device}")

    def test_mtu(self):
        """Reports on interfaces not using our MTU standards."""

        for interface in (Interface.objects.filter(device__device_role__slug__in=NETWORK_ROLES)  # Network devices
                                           .exclude(cable__isnull=True)  # Ignore interfaces with no cables
                                           .exclude(mtu=9192)  # Ignore anything with the good MTU
                                           .exclude(lag__isnull=False)  # Ignore LAG members
                                           .exclude(enabled=False)):  # Ignore disabled interfaces

            # Ignore interfaces not ultimately connected to a device
            # Eg. transit
            if not hasattr(interface.connected_endpoint, 'device'):
                continue
            z_device_name = interface.connected_endpoint.device.name
            # If connected to a server, report it
            if interface.connected_endpoint.device.device_role.slug == "server":
                self.log_failure(interface, f"[{interface.device.site.slug}] {z_device_name} switch interface "
                                            "MTU invalid (should be 9192)")

            # Core links, connected to a network device
            elif interface.connected_endpoint.device.device_role.slug in NETWORK_ROLES:
                # Ignore VC links:
                if str(interface.name).startswith('vcp-'):
                    continue
                # Report core links with different MTU on each side:
                elif interface.connected_endpoint.mtu != interface.mtu:
                    self.log_warning(interface, f"[{interface.device.site.slug}] MTU mismatch on link between "
                                                f"{interface.device.name} ({interface.mtu}) and "
                                                f"{z_device_name} ({interface.connected_endpoint.mtu})")
                    continue

                # Report any other non-standard MTU
                self.log_warning(interface, f"[{interface.device.site.slug}] {interface.device.name} core link with "
                                            f"invalid MTU ({interface.mtu})")

    def test_primary_ipv6(self):
        """Report servers that either have a missing primary_ip6 or have a primary_ip6 without a DNS name set.

        To help with T253173.
        """

        success = 0
        # Exclude fr-tech as long as they're v4 only
        for device in (Device.objects.filter(device_role__slug="server", tenant__isnull=True)
                                     .exclude(status__in=EXCLUDE_STATUSES)):
            if not device.primary_ip6:
                self.log_failure(device, "Missing primary IPv6")
                continue
            else:
                if (device.name in NO_V6_DEVICE_NAMES
                        or any(re.match(fr"{name}[1-9]", device.name) for name in NO_V6_DEVICE_NAME_PREFIXES)):
                    if device.primary_ip6.dns_name:
                        self.log_warning(
                            device, "Primary IPv6 has DNS name on a cluster that is listed as not supporting IPv6")
                        continue
                else:
                    if not device.primary_ip6.dns_name:
                        self.log_failure(device, "Primary IPv6 missing DNS name")
                        continue
            success += 1
        self.log_success(None, "{} devices with operationnal primary IPv6".format(success))

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
                self.log_failure(ipaddress, "Multiple VIPs with different prefix length")
            else:
                success += 1
        self.log_success(None, "{} correctly masked VIPs".format(success))

    def test_primary_ip_dns_match(self):
        """Check that primary IPv4/IPv6 DNS names match.

        If a device have both a primary IPv4 and IPv6 with DNS names, check that they match.  Also, check that the
        primary IPs DNS names match the hostname.
        """

        success = 0
        for device in (Device.objects.filter(device_role__slug="server", tenant__isnull=True)
                                     .exclude(status__in=EXCLUDE_STATUSES)):
            if not device.primary_ip4 or not device.primary_ip4.dns_name:
                self.log_failure(device, "Device with no primary IPv4 or DNS name")
                continue
            if not str(device.primary_ip4.dns_name).startswith(device.name + '.'):
                self.log_failure(device, "Primary IPv4 DNS ({}) doesn't start with the hostname"
                                         .format(device.primary_ip4.dns_name))

            if not device.primary_ip4 or not device.primary_ip6:
                continue
            if not device.primary_ip4.dns_name or not device.primary_ip6.dns_name:
                continue
            if device.primary_ip4.dns_name != device.primary_ip6.dns_name:
                self.log_failure(device, "Primary IPv4 and IPv6 DNS name mismatch ({} vs. {})"
                                         .format(device.primary_ip4.dns_name, device.primary_ip6.dns_name))
                continue
            else:
                success += 1
        self.log_success(None, "{} devices with matching primary IPv4 & IPv6".format(success))

    def test_mgmt_dns_hostname(self):
        """No interface on a network device should be enabled but not connected.

        Exception being management switches as we don't document them in core sites.
        """
        success = 0
        for ipaddress in IPAddress.objects.filter(interface__name="mgmt", dns_name__isnull=False).exclude(dns_name=""):
            tenant = ''
            if ipaddress.assigned_object.device.tenant and ipaddress.assigned_object.device.tenant.slug == "fr-tech":
                tenant = "frack."
            expected_fqdn = "{}.mgmt.{}{}.wmnet".format(ipaddress.assigned_object.device.name,
                                                        tenant,
                                                        ipaddress.assigned_object.device.site.slug)
            if not ipaddress.dns_name == expected_fqdn:
                self.log_failure(ipaddress.assigned_object.device,
                                 "Invalid management interface DNS ({} != {})"
                                 .format(ipaddress.dns_name, expected_fqdn))
            else:
                success += 1
        self.log_success(None, "{} correct mgmt DNS names".format(success))

    def test_matching_vlan(self):
        """Check IPs are assigned to server ports match the connected Vlan

        Every IP address bound to a host interface should come from the correct
        subnet, matching the Vlan the equivalent switch port is bound to.
        """

        success = 0
        for interface in (Interface.objects.filter(device__device_role__slug="server")
                                           .exclude(cable__isnull=True)
                                           .annotate(Count('ip_addresses'))
                                           .filter(ip_addresses__count__gte=1)):
            if interface.connected_endpoint.device.device_role.slug in ('asw', 'cloudsw'):
                for family in [4, 6]:
                    try:
                        vlan_pfx = interface.connected_endpoint.untagged_vlan.prefixes.get(prefix__family=family)
                    except Prefix.MultipleObjectsReturned:
                        self.log_failure(interface.connected_endpoint.untagged_vlan,
                                         f"Vlan has more than one IPv{family} prefix assigned")
                        vlan_pfx = interface.connected_endpoint.untagged_vlan.prefixes.filter(prefix__family=family)[0]
                    except Prefix.DoesNotExist:
                        self.log_warning(interface.connected_endpoint.untagged_vlan,
                                         f"Vlan has no IPv{family} prefix assigned.")
                        continue
                    for ip_addr in interface.ip_addresses.filter(address__family=family):
                        if (ip_addr.address.network != vlan_pfx.prefix.network
                           or ip_addr.address.prefixlen != vlan_pfx.prefix.prefixlen):
                            self.log_failure(interface.device,
                                             f"{ip_addr.address} does not match connected Vlan "
                                             f"{interface.connected_endpoint.untagged_vlan}")
                        else:
                            success += 1

        if success > 0:
            self.log_success(None, f"{success} server IP allocations matched attached switch port Vlan.")

    def test_port_block_consistency(self):
        """Validate that port types within each block of 4 are consistent for QFX5120 series

        Trident 3 based devices like the QFX5120 have a constraint that port speeds (1/10/25Gb)
        must be consistent within each block of 4 (i.e. 0-3, 4-7, 8-11 etc).  This check validates
        the data in Netbox conforms to this constraint.

        Only the SFP28 slots 0-47 are considered as the constraint does not apply to QSFP28 ports.
        """

        success = 0
        for device in (Device.objects.filter(device_type__slug="qfx5120-48y-8c")):
            port_blocks = {}
            device_failed = False
            for interface in device.interfaces.exclude(type='virtual').exclude(mgmt_only=True):
                try:
                    port = int(interface.name.split(':')[0].split('/')[-1])
                except ValueError:
                    self.log_failure(interface,
                                     f"[{device.site.slug}] Invalid interface name on Juniper QFX5120 "
                                     f"device '{device.name}'")
                    continue
                if port >= 48:
                    continue

                block = port - (port % 4)
                if block not in port_blocks.keys():
                    port_blocks[block] = interface.type
                elif port_blocks[block] != interface.type:
                    block_members = ", ".join(str(x) for x in range(block, 3)) + f" and {block+4}"
                    self.log_failure(interface,
                                     f"[{device.site.slug}] Interface type '{interface.type}' does not match "
                                     f"'{port_blocks[block]}' set on other(s) in same block on {device.name}. "
                                     f"Ports {block_members} need to be same type.")
                    device_failed = True

            if not device_failed:
                success += 1

        if success > 0:
            self.log_success(None, f"{success} QFX5120 devices have no port speed inconsistencies within blocks of 4.")
