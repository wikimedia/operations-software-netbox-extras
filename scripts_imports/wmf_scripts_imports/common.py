import ipaddress
import re

from typing import Optional, Union

from django.core.exceptions import ObjectDoesNotExist, ValidationError

from django.contrib.contenttypes.models import ContentType

from dcim.choices import CableTypeChoices, InterfaceTypeChoices, LinkStatusChoices
from dcim.models import Cable, Device, Interface, Site, VirtualChassis
from ipam.constants import IPADDRESS_ROLES_NONUNIQUE
from ipam.models import IPAddress, Prefix, VLAN
from netbox.choices import ColorChoices
from utilities.exceptions import AbortScript
from virtualization.models import VMInterface, VirtualMachine

# Prefix of neighbor interfaces names from LLDP to be considered
SWITCH_INTERFACES_PREFIX_ALLOWLIST = ("et-",
                                      "xe-",
                                      "ge-",
                                      "ethernet-")

CONFIGFILE = "/etc/netbox/reports.cfg"

PRIMARY_IFACE_NAME = "##PRIMARY##"

# Statuses that devices must be to import
IMPORT_STATUS_ALLOWLIST = ("active",
                           "failed",
                           "planned")

# Interfaces which we skip when importing
INTERFACE_IMPORT_BLOCKLIST_RE = (re.compile(r"^lo.*$"),  # Loopback
                                 re.compile(r"^docker\d+$"),  # Docker
                                 re.compile(r"^idrac$"),)  # virtual idrac device if enabled in bios

# Interface 'kinds' we skip when importing
INTERFACE_IMPORT_BLOCKLIST_KINDS = ('openvswitch', 'vxlan', 'ipip', 'ip6tnl', 'veth', 'tun')

# Hostname regexes that are immune to VIP removal because of a bug in provisioning them
# this is a temporary work around until 618766 is merged. The "VIP"s on these hosts will
# be given the netmask of the parent prefix.
NO_VIP_RE = (re.compile(r"^aqs.*"),
             re.compile(r"^restbase.*"),
             re.compile(r"^sessionstore.*"))

IFACE_TYPE_TO_JUNIPER_PREFIX = {
    InterfaceTypeChoices.TYPE_1GE_FIXED: 'ge-',
    InterfaceTypeChoices.TYPE_10GE_SFP_PLUS: 'xe-',
    InterfaceTypeChoices.TYPE_25GE_SFP28: 'et-'
}

interface_ct = ContentType.objects.get_for_model(Interface)


def format_logs(messages: list[dict]) -> str:
    """Return all log messages properly formatted."""
    return "\n".join(
        f"[{message['status']}] {message['message']}" for message in messages
    )


def port_to_iface(port: int, nbdevice: Device, interface_type: str) -> str:
    """Converts a numerical port ID, device and type to a logical interface name.

    Taking into consideration vendor specific naming, and devices constraints.
    Only for access ports.

    Arguments:
        port (int): Numerical port ID on the switch (eg. label).
        nbdevice (dcim.models.Device): Netbox device where the port is located.
        interface_type (str): Interface type/speed in a `netbox/dcim/choices.py` format.

    Returns:
        str: the logical interface name.
        None: No valid interface name possible (error)

    """
    # Specific to our only 1G model
    if interface_type != InterfaceTypeChoices.TYPE_1GE_FIXED and nbdevice.device_type.slug == "ex4300-48t":
        raise AbortScript("Switch is 1G only, interface type must be 1G")

    if nbdevice.device_type.manufacturer.slug == 'juniper':
        prefix = IFACE_TYPE_TO_JUNIPER_PREFIX[interface_type]
        if nbdevice.virtual_chassis:  # VCs are only Juniper
            return f"{prefix}{str(nbdevice.vc_position)}/0/{str(port)}"
        return f"{prefix}0/0/{str(port)}"

    if nbdevice.device_type.manufacturer.slug == 'nokia':
        return f"ethernet-1/{str(port)}"

    raise AbortScript("Unsupported switch vendor (must be Nokia or Juniper)")


def duplicate_cable_id(cable_id: int, site: Site) -> bool:
    """Check if the cable ID (label) is already in use at a given site.

    Arguments:
        cable_id (int): ID/label printed on the cable.
        site (dcim.models.Site): Netbox site where to check for duplicates.

    Returns:
        bool: The cable ID is already used or not.

    """
    cables_with_same_id = Cable.objects.filter(label=cable_id)
    for cable in cables_with_same_id:
        for termination in cable.terminations.all():
            if isinstance(termination, Interface) and termination.device.site == site:
                # TODO: raise AbortScript ?
                return True
    return False


def find_tor(server: Device) -> Optional[Device]:
    """Return the ToR switch a server should be connected to.

    Arguments:
        server (dcim.models.Device): Netbox device we're interested in.

    Returns:
        dcim.models.Device: A ToR switch.

    """
    switch = Device.objects.filter(rack=server.rack,
                                   role__slug__in=('asw', 'cloudsw'),
                                   status='active')
    if len(switch) > 1:  # TODO raise AbortScript once Netbox is upgraded ?
        return None
    return switch[0]


class Importer:
    """Shared functionality for interface and IP address importers."""

    @staticmethod
    def _get_ipv6_prefix_length(ipv6mask: str) -> int:
        """Convert an old-style IPv6 netmask into a prefix length in bits.

        This is provided because the ipaddress library does not support this (deprecated) method
        of specifying the host bits, however this is how PuppetDB provides the information.

        Arguments:
            ipv6mask (str): An IPv6 netmask

        Returns:
            int: The number of network prefix bits contained in the netmask.

        """
        counts = [
            0,
            0x8000,
            0xC000,
            0xE000,
            0xF000,
            0xF800,
            0xFC00,
            0xFE00,
            0xFF00,
            0xFF80,
            0xFFC0,
            0xFFE0,
            0xFFF0,
            0xFFF8,
            0xFFFC,
            0xFFFE,
            0xFFFF,
        ]

        length = 0

        for chunk in ipv6mask.split(":"):
            if not chunk:
                break

            chunk_int = int(chunk, 16)
            if chunk_int == 0:
                break

            length += counts.index(chunk_int)

        return length

    def _assign_ip_to_interface(self, address, nbiface, networking, iface, is_primary, is_ipv6):
        """Assign an IP address to an interface as specified by a PuppetDB interface fact."""
        ipaddr_changed = False
        newdev_changed = False
        # heuristically determine if this is probably anycast
        if iface.startswith("lo:anycast"):
            self.log_info(f"{address} on {iface} is being assigned as anycast.", obj=nbiface)
            role = "anycast"
        else:
            role = ""

        # try to get the existing ip address object from netbox
        try:
            ipaddr = IPAddress.objects.get(address=str(address))
        except ObjectDoesNotExist:
            self.log_info(f"Creating {address} and assigning to interface '{nbiface.name}'", obj=nbiface)
            ipaddr = IPAddress(address=str(address),
                               assigned_object=nbiface, role=role)
            ipaddr.save()

        if ipaddr.role in IPADDRESS_ROLES_NONUNIQUE:
            self.log_warning(f"Skipping assigning existing IP {address} with role {ipaddr.role} to {iface}. "
                             f"The IP might have the wrong netmask (expected /32 or /128 for VIP-like IPs)",
                             obj=ipaddr)

        oldiface = ipaddr.assigned_object
        if oldiface:
            if hasattr(oldiface, 'virtual_machine'):
                olddev = oldiface.virtual_machine
            else:
                olddev = oldiface.device
        else:
            olddev = None

        if hasattr(nbiface, 'virtual_machine'):
            newdev = nbiface.virtual_machine
        else:
            newdev = nbiface.device

        if not ipaddr.assigned_object:
            # no interface assigned
            self.log_info(f"Assigning {address} to {newdev}:{nbiface}", obj=nbiface)
        elif olddev != newdev:
            # the ip address is assigned to a completely different device
            # and this is not a vdev, reassign
            self.log_info(f"Taking IP address {ipaddr} from {olddev}:{ipaddr.assigned_object}", obj=ipaddr)
            self.log_info(f"Assigning {address} to {newdev}:{nbiface}", obj=nbiface)
            if is_ipv6 and olddev is not None and olddev.primary_ip6 == ipaddr:
                olddev.primary_ip6 = None
            elif not is_ipv6 and olddev is not None and olddev.primary_ip4 == ipaddr:
                olddev.primary_ip4 = None
            olddev.save()
        else:
            # on same device but different interface
            if ipaddr.assigned_object.name not in networking["interfaces"]:
                # basically renaming a device so we need to copy the description field
                nbiface.description = ipaddr.assigned_object.description
                nbiface.save()

        # finally actually reassign interface

        if (ipaddr.assigned_object != nbiface
           or ipaddr.description == "reserved for infra"
           or ipaddr.role != role
           or ipaddr.status != "active"):
            ipaddr.assigned_object = nbiface
            ipaddr.description = ""
            ipaddr.role = role
            ipaddr.status = "active"
            ipaddr_changed = True

        if ipaddr.status != "active" or ipaddr.status is None:
            self.log_info(f"Non-active IP address {ipaddr} being assigned, old status {ipaddr.status}", obj=ipaddr)

        if is_primary:
            # Try assigning DNS name and getting information about DNS.
            if ipaddr.dns_name == networking["fqdn"]:
                self.log_info(f"{networking['fqdn']} assign_name: {ipaddr.address} already has correct DNS name.",
                              obj=ipaddr)
            elif ipaddr.dns_name:
                self.log_failure((f"{networking['fqdn']} assign_name: {ipaddr.address} has a different DNS name than"
                                  f" expected: {ipaddr.dns_name}"), obj=ipaddr)

            if is_ipv6 and (newdev.primary_ip6 != ipaddr):
                ipaddr.is_primary = True
                ipaddr_changed = True
                newdev.primary_ip6 = ipaddr
                newdev_changed = True
                self.log_info(f"Setting {ipaddr} as primary for {newdev}", obj=ipaddr)
            elif not is_ipv6 and (newdev.primary_ip4 != ipaddr):
                ipaddr.is_primary = True
                ipaddr_changed = True
                newdev.primary_ip4 = ipaddr
                newdev_changed = True
                self.log_info(f"Setting {ipaddr} as primary for {newdev}", obj=ipaddr)
            else:
                self.log_info(f"{ipaddr} is already primary for {newdev}", obj=ipaddr)

        if newdev_changed:
            newdev.save()

        if ipaddr_changed:
            ipaddr.save()

    def _process_binding_address(self, binding, is_ipv6, is_anycast, vip_exempt):
        """Convert a binding to an ipaddress.ip_interface object.

        The binding may be considered for VIP processing, instead of being considered for attaching
        to an interface.
        Arguments:
            binding (dict): A dictionary describing the binding
            is_ipv6 (bool): indicate if the binding is for an ipv6 address
            is_anycast (bool): indicate if the binding is for an anycast address
            vip_exempt (bool): indicate if the binding is for a binding exampt from vip processing

        Returns:
            (ipaddress.ip_interface, None): if the binding is a VIP or SLAAC address return None,
                otherwise return the converted ipaddress.ip_interface object.

        """
        addr = binding["address"]
        if is_ipv6:
            # we need to translate the netmask6 exposed by puppet into a prefix length since ipaddress
            # library does not support this case.
            nm = self._get_ipv6_prefix_length(binding["netmask"])
        else:
            nm = binding["netmask"]

        address = ipaddress.ip_interface(f"{addr}/{nm}")

        if ((address.is_link_local) or (address.is_loopback)):
            # We skip link local and loopback addresses
            return None

        # Warn the user if one of the IP is an auto-config IP and skip it
        if is_ipv6 and address.exploded[27:32] == 'ff:fe':
            self.log_warning(f"{address}: skipping SLAAC IP")
            return None

        # Netbox always sorts the prefixes, .last() is the one closest to the given IP
        parent_prefix = Prefix.objects.filter(prefix__net_contains=str(address)).last()
        if not parent_prefix:
            self.log_failure(f"Can't find parent prefix for {address}.")
            return None

        if address.network.prefixlen in (32, 128) and vip_exempt:
            # FIXME
            # this is a bug in our deployment of certain servers where some service addresses have
            # a /32 or /128 netmask but aren't actually VIPs, need to figure out the correct netmask
            realnetmask = parent_prefix.prefix.prefixlen
            address = ipaddress.ip_interface(f"{addr}/{realnetmask}")
            self.log_info("VIP exempt: Overriding provided netmask")

        # Don't treat /32-/128 IPs in routed VM ranges as VIPs
        if is_anycast or (address.network.prefixlen in (32, 128)
                          and getattr(parent_prefix.role, 'slug', '') != 'virtual-machines'):
            self._handle_vip(address, is_anycast)
            return None

        return address

    def _handle_vip(self, address, is_anycast):
        """Do special processing for a potential VIP that will not be bound to an interface."""
        # Given a VIP, handle directly rather than processing with a host interface.
        role = "anycast" if is_anycast else "vip"
        try:
            ipaddrs = IPAddress.objects.filter(address=str(address))
            if ipaddrs.count() > 1:
                self.log_debug(f"{address} has multiple results, taking the 0th one", obj=ipaddrs[0])
            elif ipaddrs.count() == 0:
                raise ObjectDoesNotExist()
            ipaddr = ipaddrs[0]
            if ipaddr.role != role or ipaddr.assigned_object is not None or ipaddr.status != "active":
                ipaddr.role = role
                # We specially handle VIP addresses but do not allow them to be bound
                ipaddr.assigned_object = None
                ipaddr.status = "active"
                ipaddr.save()
                self.log_success(f"{address}: {role}, set to no interface and active", obj=ipaddr)
        except ObjectDoesNotExist:
            ipaddr = IPAddress(address=str(address),
                               assigned_object=None, role=role,
                               status='active')
            ipaddr.save()
            self.log_success(f"{address}: created, {role}, no interface and active", obj=ipaddr)

    def _get_vc_member(self, neighbor, interface):
        """Return a Netbox VC member device based on a hostname and an interface."""
        virtual_chassis = VirtualChassis.objects.get(domain__startswith=neighbor)
        if not virtual_chassis:
            return None

        # Extract the VC member position from the interface name
        try:
            vcp_number = int(interface.split('-')[1].split('/')[0])
        except (AttributeError, IndexError, ValueError):
            return None
        for vc_member in Device.objects.filter(virtual_chassis=virtual_chassis):
            # If any match, return it
            if vc_member.vc_position == vcp_number:
                return vc_member
        return None

    def _get_z_interface(self, lldp_iface):
        """Return the Netbox objects of a LLDP neighbor (device/interface), create it if needed."""
        # Thanks to Juniper we have either the hostname or FQDN (see PR1383295)
        if '.' in lldp_iface['neighbor']:
            z_device = lldp_iface['neighbor'].split('.')[0]
        else:
            z_device = lldp_iface['neighbor']
        z_iface = lldp_iface['port']
        # First we try to see if the neighbor name match a device
        try:
            z_nbdevice = Device.objects.get(name=z_device)  # Z for remote side
        except ObjectDoesNotExist:
            # If not we have to get the proper VC member
            z_nbdevice = self._get_vc_member(z_device, z_iface)

        try:
            z_nbiface = z_nbdevice.interfaces.get(name=z_iface)
        except ObjectDoesNotExist:  # If interface doesn't exist: create it
            mtu = None
            if 'mtu' in lldp_iface and lldp_iface['mtu'] != 1514:  # Get MTU but ignore the default one
                mtu = lldp_iface['mtu']

            z_nbiface = self._create_z_nbiface(z_nbdevice, z_iface, mtu)

        return z_nbiface

    def _create_z_nbiface(self, z_nbdevice, z_iface, mtu=None, iface_fmt=None):
        """Create new int on device and return netbox object."""
        if (z_iface.startswith(SWITCH_INTERFACES_PREFIX_ALLOWLIST)
                and z_nbdevice.device_type.manufacturer.slug == 'juniper'):
            self._delete_orphan_nbiface(z_nbdevice, z_iface)

        if not iface_fmt:
            iface_fmt = self._get_iface_fmt(z_iface)

        z_nbiface = Interface(name=z_iface,
                              mgmt_only=False,
                              device=z_nbdevice,
                              type=iface_fmt,
                              mtu=mtu)
        # Run interface validator to ensure port-block consistency
        try:
            z_nbiface.full_clean()
        except ValidationError as e:
            raise AbortScript(f"{z_nbdevice}: interface {z_iface} fails validation checks - {e.messages[0]}.") from e

        z_nbiface.save()
        self.log_success(f"{z_nbdevice}: created interface {z_iface}", obj=z_iface)
        return z_nbiface

    def _delete_orphan_nbiface(self, z_nbdevice, z_iface):
        """Look for orphan int, renamed on device due to optic change, and delete if found."""
        port_num = z_iface.split("-")[1]
        for z_nbdevice_int in Interface.objects.filter(
            device_id=z_nbdevice.id,
            name__iregex=f"^({'|'.join(SWITCH_INTERFACES_PREFIX_ALLOWLIST)}){port_num}$"
        ):
            if z_nbdevice_int.connected_endpoints or z_nbdevice_int.count_ipaddresses > 0:
                raise AbortScript(f"{z_nbdevice.name}: We need to remove interface {z_nbdevice_int.name}, before "
                                  f"creating {z_iface}, however it still has a cable or IP address attached. "
                                  "See https://wikitech.wikimedia.org/wiki/Netbox"
                                  "#Error_removing_interface_after_speed_change")

            z_nbdevice_int_name = z_nbdevice_int.name
            z_nbdevice_int.delete()
            self.log_success(f"{z_nbdevice}: deleted orphan interface {z_nbdevice_int_name}", obj=z_nbdevice)

    def _get_iface_fmt(self, iface_name):
        """Returns iface_fmt object for correct PHY type based on Juniper interface naming conventions."""
        return {
            'xe-': InterfaceTypeChoices.TYPE_10GE_SFP_PLUS,
            'et-': InterfaceTypeChoices.TYPE_25GE_SFP28,
        }.get(iface_name[0:3], InterfaceTypeChoices.TYPE_1GE_FIXED)

    def _update_z_vlan(self, device_interface):
        """Update switch-port vlans if they don't match those on host."""
        if not (device_interface.mode and device_interface.connected_endpoints):
            return
        # Only works with 1 connected endpoint (Netbox 4 upgrade)
        z_nbiface = device_interface.connected_endpoints[0]
        int_changed = False
        if not z_nbiface.mode:
            z_nbiface.mode = device_interface.mode
            int_changed = True
            self.log_info(f"Set {z_nbiface.device.name} {z_nbiface.name} mode to "
                          f"{z_nbiface.mode} matching {device_interface.name}", obj=z_nbiface)

        if device_interface.untagged_vlan != z_nbiface.untagged_vlan:
            z_nbiface.untagged_vlan = device_interface.untagged_vlan
            int_changed = True
            self.log_info(f"Set {z_nbiface.device.name} {z_nbiface.name} untagged vlan to "
                          f"{z_nbiface.untagged_vlan} matching {device_interface.name}", obj=z_nbiface)

        tagged_vlans = list(device_interface.tagged_vlans.all())
        if tagged_vlans != list(z_nbiface.tagged_vlans.all()):
            z_nbiface.tagged_vlans.set(tagged_vlans)
            int_changed = True
            self.log_info(f"Set {z_nbiface.device.name} {z_nbiface.name} tagged vlans to "
                          f"{tagged_vlans} matching {device_interface.name}", obj=z_nbiface)

        if int_changed:
            z_nbiface.save()

    def _update_cable(self, lldp_iface, nbiface, z_nbiface):
        """Create or update a cable between two interfaces."""
        # First we check if there is a cable on either sides
        nbcable = nbiface.cable
        z_nbcable = z_nbiface.cable

        # Get the cable ID if any
        label = ''
        if 'descr' in lldp_iface:
            re_search = re.search('{#(?P<cable_id>[^}]+)}', lldp_iface['descr'])
            if re_search:
                label = re_search.groupdict()['cable_id']

        # If the cables on both sides don't match delete them
        # As well as if only one side exist (as it can't go to the good place)
        if nbcable != z_nbcable:
            if nbcable is not None:
                self.log_success(f"{nbiface.device}: Remove cable from {nbiface}", obj=nbiface)
                nbcable.delete()
                # After deleting the cable refresh the interface, otherwise
                # nbiface.cable still returns the old cable
                nbiface.refresh_from_db()
            if z_nbcable is not None:
                self.log_success(f"{z_nbiface.device}: remove cable from {z_nbiface}", obj=z_nbiface)
                z_nbcable.delete()
                # After deleting the cable refresh the interface, otherwise
                # z_nbiface.cable still returns the old cable
                z_nbiface.refresh_from_db()
        elif nbcable is not None:
            # If they match and are not None, we still need to check if the cable ID is good
            if label and nbcable.label != label:
                nbcable.label = label
                self.log_success(f"{nbiface.device}: update label for {nbcable}: {label}", obj=nbcable)
                nbcable.save()
        # Now we either have a fully correct cable, or nbcable == z_nbcable == None
        # In the 2nd case, we create the cable
        if nbcable is None:
            self._create_cable(nbiface, z_nbiface, label=label)

    def _get_parent_interface(self, device, int_puppet_facts, parent_type):
        """Returns the Netbox interface object referenced in another interface's Puppet facts.

        As its 'parent_bridge' or 'parent_link'.

        Inputs:
            device:      netbox device object the interface belongs to
            int_puppet_facts:  puppetdb networking facts for the specific interface
            parent_type: either 'parent_link' if we want to fetch the physical network
                        interface of a vlan sub-int, or 'parent_bridge' if we are
                        trying to fetch a bridge device.

        Returns:
            Netbox interface object of parent.  None if the puppet facts don't list
            any parent of requested type, or they do but no NB int of that name exists.

        """
        try:
            return Interface.objects.get(name=int_puppet_facts[parent_type], device=device)
        except (Interface.DoesNotExist, KeyError):
            return None

    def _make_interface_vm(self, device, iface, mtu):
        # only set MTU if it is non-default and not a loopback
        nbiface = VMInterface(name=iface,
                              virtual_machine=device,
                              mtu=mtu)

        nbiface.save()
        return nbiface

    def _make_interface(self, device, iface, net_driver, is_vdev, mtu):
        # this is the default 'type' for the device
        iface_fmt = InterfaceTypeChoices.TYPE_1GE_FIXED
        if is_vdev:
            # if it's identified as a virtual device, we make it virtual
            iface_fmt = InterfaceTypeChoices.TYPE_VIRTUAL
        elif iface in net_driver:
            # otherwise if the speed is 10000 we make it 10GE
            if net_driver[iface]["speed"] == 10000:
                iface_fmt = InterfaceTypeChoices.TYPE_10GE_SFP_PLUS

        nbiface = Interface(name=iface,
                            mgmt_only=False,
                            device=device,
                            type=iface_fmt,
                            mtu=mtu)

        nbiface.save()
        return nbiface

    def _update_int_relations(self, device, nbiface, int_puppet_facts, is_vm):
        """Sets or updates interface link parents, bridge membership and vlan settings as required.

        Inputs:
            device: Netbox device object
            nbiface: Netbox interface object
            int_puppet_facts: puppetdb networking facts for the specific interface
            is_vm: if the current device is a Virtual Machine

        Returns: None

        """
        # Create attachment to related interfaces
        for parent_type in ['parent_bridge', 'parent_link']:
            parent = self._get_parent_interface(device, int_puppet_facts, parent_type)
            if parent_type in int_puppet_facts and not parent:
                raise AbortScript(f"PuppetDB reports {nbiface.name} has {parent_type} called"
                                  f"{{ int_puppet_facts[parent_type] }} but no matching int in Netbox")
            # NB uses differnt terms for related ints
            nb_parent_type = 'parent' if parent_type == 'parent_link' else 'bridge'
            # If parent on Netbox int doesn't match what PuppetDB says then set it
            if getattr(nbiface, nb_parent_type, None) != parent:
                setattr(nbiface, nb_parent_type, parent)
                self.log_info(f"Attach interface {nbiface.name} to {parent_type} {parent}", obj=nbiface)

        # If it's a special type of int set type (physical only)
        if "kind" in int_puppet_facts and not is_vm:
            if int_puppet_facts['kind'] == "vlan":
                # Make sure it's virtual and access vlan set on it, plus tagged on its parent
                nbiface.type = InterfaceTypeChoices.TYPE_VIRTUAL
                self._set_subint_vlan(nbiface, int_puppet_facts)
            elif int_puppet_facts['kind'] == "bridge" and nbiface.type != InterfaceTypeChoices.TYPE_BRIDGE:
                nbiface.type = InterfaceTypeChoices.TYPE_BRIDGE
                self.log_info(f"Set interface '{nbiface.name}' to type bridge.", obj=nbiface)

        nbiface.save()

    def _set_subint_vlan(self, nbiface, int_puppet_facts):
        """Sets 802.1q sub-int and parent int mode, adds vlan to list for both.

        Sub-interfaces are set to type 'access', with the access vlan set.
        Parents are set to type 'trunk' (if not already), and vlan from sub-int is
        added to its 'tagged_vlans'.

        Inputs:
            nbiface:    netbox interface object
            int_puppet_facts: puppetdb networking facts for the specific interface

        """
        try:
            subint_vlan = VLAN.objects.get(vid=int_puppet_facts['dot1q'], site=nbiface.device.site.id)
        except ObjectDoesNotExist:
            self.log_warning(f"Configured Vlan ID {int_puppet_facts['dot1q']} on {nbiface.name} not found in Netbox",
                             obj=nbiface)
            return

        # Set subint parent to tagged mode if required, and add vlan for this subint to it
        if nbiface.parent.mode != "tagged":
            self._make_interface_tagged(nbiface.parent)
        nbiface.parent.tagged_vlans.add(subint_vlan.id)
        nbiface.parent.save()
        self.log_info(f"Added vlan {int_puppet_facts['dot1q']} to {nbiface.parent.name} tagged vlans", obj=nbiface)
        # Set correct untagged vlan for this sub-int
        nbiface.mode = "access"
        nbiface.untagged_vlan_id = subint_vlan.id
        self.log_info(f"Set vlan {int_puppet_facts['dot1q']} as untagged vlan on {nbiface.name}", obj=nbiface)

    def _make_interface_tagged(self, nbiface):
        """Sets netbox interface mode to 'tagged'.

        Where the interface has an IP address directly connected we find the vlan associated
        with that IP and set it as the untagged vlan for the interface.

        Inputs:
            nbiface: netbox interface object
        """
        nbiface.mode = 'tagged'
        # Set untagged_vlan based on interface IP if present
        if nbiface.bridge:
            # If interface is a bridge member it should have no IPs, they'll instead be bound to bridge
            int_ips = list(nbiface.bridge.ip_addresses.all())
        else:
            int_ips = list(nbiface.ip_addresses.filter())
        if int_ips:
            int_ip = int_ips[0].address
            parent_prefix = Prefix.objects.get(prefix=f"{int_ip.network}/{int_ip.prefixlen}")
            nbiface.untagged_vlan_id = parent_prefix.vlan.id
        # Save here as that's required before tagged_vlans can be set
        nbiface.save()

    def _get_ordered_ints(self, interfaces):
        """Returns ordered list of interface names from Puppet data

        Interates over interface names from Puppet data, and returns list of them
        in order that is required for Netbox addition. Specifically bridges need to
        be added first, then vlan sub-int parents, then the rest.

        Inputs:
            interfaces: puppetdb networking facts for all the device interfaces

        Returns:
            int_names:  list of interface names in the order they need to be processed

        """
        # Iterate over ints, add bridges to int_names, and record vlan_parents
        int_names = []
        vlan_parents = set()
        for iface_name, iface_facts in interfaces.items():
            # We skip certain interfaces based on their kind
            if iface_facts.get('kind', '') in INTERFACE_IMPORT_BLOCKLIST_KINDS:
                self.log_info(f"Skipping {iface_name} as we do not import {iface_facts['kind']} interfaces.")
                continue
            if iface_facts.get('kind', '') == "bridge":
                int_names.append(iface_name)
            if "parent_link" in iface_facts:
                vlan_parents.add(iface_facts['parent_link'])
        # Append first the vlan parents then remaining ints to list and return
        int_names = int_names + list(vlan_parents)
        int_names = int_names + [name for name in interfaces.keys() if name not in int_names]
        return int_names

    def _import_interfaces_for_device(self, device: Device, net_driver: dict,
                                      networking: dict, lldp: dict, is_vm: bool = False) -> list:
        # TODO: docstring
        # Resolve one device's interfaces and ip addresses based on a net_driver, networking and lldp dictionary
        # as would be obtained from PuppetDB under those key names.
        output: list = []

        for device_interface in device.interfaces.all():
            # Clean up potential ##PRIMARY## interfaces
            if device_interface.name == PRIMARY_IFACE_NAME and 'primary' in networking:
                primary_int_name = networking['primary']
                if networking['interfaces'][primary_int_name].get('kind', '') == 'bridge':
                    # If puppet primary int is a bridge, find the attached physical instead
                    for iface_name, iface_detail in networking['interfaces'].items():
                        if (iface_detail.get('parent_bridge', '') == primary_int_name
                                and lldp.get(iface_name, {}).get('router', False)):
                            primary_int_name = iface_name
                            break

                device_interface.name = primary_int_name
                if not is_vm:
                    if net_driver[primary_int_name]["speed"] == 10000:
                        device_interface.type = InterfaceTypeChoices.TYPE_10GE_SFP_PLUS
                device_interface.save()
                self.log_success(f"{device.name}: renamed ##PRIMARY## interface to {device_interface.name}",
                                 obj=device_interface)

        # Import in correct order so parents added before children
        ordered_ints = self._get_ordered_ints(networking['interfaces'])
        for iface in ordered_ints:
            int_puppet_facts = networking['interfaces'][iface]
            is_vdev = ((":" in iface) or ("." in iface) or ("lo" == iface))
            is_anycast = iface.startswith("lo:anycast")
            if any(r.match(iface) for r in INTERFACE_IMPORT_BLOCKLIST_RE):
                # don't create interfaces for blocklisted iface, but we still want to process
                # their IP addresses.
                nbiface = None
            else:
                try:
                    nbiface = device.interfaces.get(name=iface)
                except ObjectDoesNotExist:
                    self.log_info(f"Creating interface {iface} for device {device}", obj=device)
                    # only set MTU if it is non-default and not a loopback
                    mtu = None
                    if int_puppet_facts.get(mtu, 1500) != 1500 and iface != "lo":
                        mtu = int_puppet_facts["mtu"]
                    if is_vm:
                        nbiface = self._make_interface_vm(device, iface, mtu)
                    else:
                        nbiface = self._make_interface(device, iface, net_driver, is_vdev, mtu)

                # Update interface parent, bridge and set vlans if needed
                self._update_int_relations(device, nbiface, int_puppet_facts, is_vm)

            # FIXME /32 bug things here
            vipexempt = any(r.match(device.name) for r in NO_VIP_RE)
            # process ipv4 addresses
            for binding in int_puppet_facts.get('bindings', []):
                address = self._process_binding_address(binding, False, is_anycast, (vipexempt and not is_vdev))
                if address is None:
                    continue
                if address in ipaddress.IPv4Network('192.168.0.0/16'):  # non-routed network, ignore it
                    continue
                is_primary = (iface == networking['primary'] and str(address.ip) == networking['ip'])
                self._assign_ip_to_interface(address, nbiface, networking, iface, is_primary, False)
            # process ipv6 addresses
            for binding in int_puppet_facts.get('bindings6', []):
                address = self._process_binding_address(binding, True, is_anycast, (vipexempt and not is_vdev))
                if address is None:
                    continue
                # the primary ipv6 address is currently a mapped ipv6 address so it should end with networking['ip']
                is_primary = (iface == networking['primary']
                              and str(address.ip).endswith(networking['ip'].replace('.', ':')))
                self._assign_ip_to_interface(address, nbiface, networking, iface, is_primary, True)
            # Now that we have tackled the interfaces and their IPs, it's time for the cables and vlan using LLDP
            # If neighbor + port set, find the real switch (either standalone or VC member)
            if iface in lldp and 'neighbor' in lldp[iface] and 'port' in lldp[iface]:
                # We want to filter some of the returned LLDP entries.
                # For example on hosts like Ganeti, VMs show up as:
                # {'neighbor': schema1003.eqiad.wmnet', 'descr': 'ens5', 'port': 'aa:00:00:88:83:8a'}
                if not lldp[iface]['port'].startswith(SWITCH_INTERFACES_PREFIX_ALLOWLIST):
                    continue
                # First we get or create the remote interface
                z_nbiface = self._get_z_interface(lldp[iface])

                # If nbiface already existed, or LLDP reports switch has 1514 MTU, nbiface.mtu may not be set,
                # but as this is a L2 switch port we should set 9192 to avoid risk of lowering IRB MTU (T329535)
                if not z_nbiface.mtu:
                    z_nbiface.mtu = 9192
                    z_nbiface.save()
                    self.log_info(f"Updated {z_nbiface.device.name} {z_nbiface.name} MTU to 9192", obj=z_nbiface)

                # Create or update the cable if devices not already connected
                # Only works with 1 connected endpoint (Netbox 4 upgrade)
                if not (nbiface.connected_endpoints and nbiface.connected_endpoints[0] == z_nbiface):
                    self._update_cable(lldp[iface], nbiface, z_nbiface)

        # Once all interfaces have been added to the device we can clean up any inconsistencies.
        # First remove any child interfaces that are no longer in PuppetDB
        for child_interface in device.interfaces.filter(parent__isnull=False):
            if child_interface.name not in networking["interfaces"]:
                self.log_info(f"{device.name}: removing child interface no longer in puppet {child_interface.name}",
                              obj=device)
                child_interface.delete()

        # Now process the remaining interfaces
        for device_interface in device.interfaces.all():
            # Update switch-port vlans if they don't match those on host
            self._update_z_vlan(device_interface)
            # Remove any netbox interfaces that aren't in puppet facts if it's safe
            if (device_interface.name not in networking["interfaces"]
               and device_interface.name not in ("mgmt", "##PRIMARY##")):
                # clean up interface if there are no IPs assigned, and there are no cables connected
                if device_interface.count_ipaddresses == 0 and (
                        (hasattr(device_interface, 'cable') and device_interface.cable is None)
                        or hasattr(device_interface, 'virtual_machine')):
                    self.log_info(f"{device.name}: removing interface no longer in puppet {device_interface.name}",
                                  obj=device)
                    device_interface.delete()
                else:
                    self.log_failure(f"{device.name}: We want to remove interface {device_interface.name}, however "
                                     "it still has a cable or IP address associated with it. "
                                     "See https://wikitech.wikimedia.org/wiki/Netbox#Would_like_to_remove_interface",
                                     obj=device_interface)
        return output

    def _validate_device(self, device: Union[Device, VirtualMachine]) -> bool:
        """Check if device is OK for import."""
        # Devices should be in the STATUS_ALLOWLIST to import
        if device.status not in IMPORT_STATUS_ALLOWLIST:
            self.log_failure(
                f"{device} has an inappropriate status (must be one of {IMPORT_STATUS_ALLOWLIST}): {device.status}",
                obj=device
            )
            return False

        return True

    def _create_cable(self, nbiface, z_nbiface, label=''):
        """Create a cable between two interfaces."""
        color = ''
        cable_type = ''
        color_human = ''
        # Most of our infra are either blue 1G copper, or black 10G DAC.
        # Exceptions are yellow fibers for longer distances like LVS, or special sites like ulsfo
        if nbiface.type == InterfaceTypeChoices.TYPE_1GE_FIXED:
            color = ColorChoices.COLOR_BLUE
            color_human = dict(ColorChoices)[color]
            cable_type = CableTypeChoices.TYPE_CAT5E
        elif nbiface.type in (InterfaceTypeChoices.TYPE_10GE_SFP_PLUS, InterfaceTypeChoices.TYPE_25GE_SFP28):
            color = ColorChoices.COLOR_BLACK
            color_human = dict(ColorChoices)[color]
            cable_type = CableTypeChoices.TYPE_DAC_PASSIVE

        cable = Cable(a_terminations=[nbiface],
                      b_terminations=[z_nbiface],
                      label=label,
                      color=color,
                      type=cable_type,
                      status=LinkStatusChoices.STATUS_CONNECTED)
        cable.save()
        self.log_success(f"{nbiface.device}: created cable {cable}", obj=cable)
        self.log_warning(f"{nbiface.device}: assuming {color_human} {cable_type} because {nbiface.type}", obj=nbiface)

    def _update_z_nbiface(self, z_nbdevice, z_iface, vlan, iface_fmt=None, tagged_vlans=None) -> Interface:
        """Create switch interface if needed and set vlan info."""
        try:
            # Try to find if the interface exists
            z_nbiface = z_nbdevice.interfaces.get(name=z_iface)
            if z_nbiface.cable:
                raise AbortScript(f"There is already a cable on {z_nbiface.device}:{z_nbiface} (typo?), "
                                  "please fix it manually and re-run the script.")
        except ObjectDoesNotExist:  # If interface doesn't exist: create it
            z_nbiface = self._create_z_nbiface(z_nbdevice, z_iface, 9192, iface_fmt)
            z_nbiface.save()

        # Then configure it - operations need to be in this order, and iface saved before tagged vlans added
        z_nbiface.mode = 'access'
        z_nbiface.mtu = 9192
        z_nbiface.untagged_vlan = vlan
        z_nbiface.enabled = True
        if tagged_vlans:
            z_nbiface.mode = 'tagged'
            z_nbiface.save()
            z_nbiface.tagged_vlans.set(tagged_vlans)
            self.log_success(f"{z_nbiface.device}:{z_nbiface} configured tagged vlans "
                             f"{[vlan.name for vlan in z_nbiface.tagged_vlans.all()]}", obj=z_nbiface)
        z_nbiface.save()
        self.log_success(f"{z_nbiface.device}:{z_nbiface} configured vlan.", obj=z_nbiface)
        return z_nbiface

    def find_primary_interface(self, device: Device) -> Optional[Interface]:
        """For regular servers, return the primary interface."""
        ifaces_connected = device.interfaces.filter(mgmt_only=False, cable__isnull=False)
        if len(ifaces_connected) != 1:
            ifaces_list = ", ".join(i.name for i in ifaces_connected)
            # TODO replace with raise AbortScript ?
            self.log_failure(f"{device}: either 0 or more than 1 connected interface: {ifaces_list},"
                             f" please update Netbox manually, skipping.", obj=device)
            return None
        # At this point there is only the one.
        return ifaces_connected[0]

    def clean_interface(self, interface: Interface):
        """Reset the interface's attributes."""
        interface.enabled = False
        interface.mode = ''
        interface.untagged_vlan = None
        interface.mtu = None
        interface.tagged_vlans.set([])
        interface.save()

    def find_remote_interface(self, interface: Interface) -> Optional[Interface]:
        """Returns the remote side interface connected to an interface."""
        cable = interface.cable
        if not cable:
            return None
        for termination in cable.terminations.all():
            if termination.termination != interface and isinstance(termination.termination, Interface):
                return termination.termination
        return None
