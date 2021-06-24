"""
Report on various network related errors.

"""

from collections import defaultdict

from dcim.choices import DeviceStatusChoices
from dcim.constants import VIRTUAL_IFACE_TYPES
from ipam.constants import IPADDRESS_ROLES_NONUNIQUE

from dcim.models import Device, Interface
from extras.reports import Report
from ipam.models import IPAddress

EXCLUDE_STATUSES = (
    DeviceStatusChoices.STATUS_DECOMMISSIONING,
    DeviceStatusChoices.STATUS_INVENTORY,
    DeviceStatusChoices.STATUS_OFFLINE,
    DeviceStatusChoices.STATUS_PLANNED,
)
SWITCHES_ROLES = ("asw", "msw", "cloudsw")
NETWORK_ROLES = ("asw", "cr", "mr", "pfw", "cloudsw")


ACCESS_INTERFACES_PREFIX = ("xe-", "ge-")


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
            self.log_failure(interface, "Interface enabled but not connected on {}".format(interface.device))

    def test_primary_ipv6(self):
        """Report servers that either have a missing primary_ip6 or have a primary_ip6 without a DNS name set.

        To help with T253173.
        """

        success = 0
        # Exclude fr-tech as long as they're v4 only
        for device in (Device.objects.filter(device_role__slug="server", tenant__isnull=True)
                                     .exclude(status__in=EXCLUDE_STATUSES)):
            if not device.primary_ip6:
                self.log_warning(device, "Missing primary IPv6")
                continue
            else:
                if not device.primary_ip6.dns_name:
                    self.log_warning(device, "Primary IPv6 missing DNS name")
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
                self.log_failure(device, "Primary IPv4 and IPv6 DNS name missmatch ({} vs. {})"
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
        for ipaddress in IPAddress.objects.filter(interface__name="mgmt", dns_name__isnull=False):

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
