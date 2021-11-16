import configparser
import csv
import io
import ipaddress
import re
import json

import requests

from string import ascii_lowercase

from django.core.exceptions import ObjectDoesNotExist

from django.contrib.contenttypes.models import ContentType

from dcim.choices import CableStatusChoices, CableTypeChoices, InterfaceTypeChoices
from dcim.models import Cable, Device, Interface, VirtualChassis
from extras.scripts import BooleanVar, ChoiceVar, FileVar, ObjectVar, Script, StringVar, TextVar
from ipam.constants import IPADDRESS_ROLES_NONUNIQUE
from ipam.models import IPAddress, Prefix, VLAN
from ipam.filters import PrefixFilterSet
from utilities.choices import ColorChoices
from virtualization.models import VirtualMachine, VMInterface

CONFIGFILE = "/etc/netbox/reports.cfg"

# Interfaces which we skip when importing
INTERFACE_IMPORT_BLOCKLIST_RE = (re.compile(r"^cali.*"),  # Kubernetes
                                 re.compile(r"^tap.*"),  # Ganeti & Openstack
                                 re.compile(r"^lo.*$"),)  # Loopback

# PTRs that we skip when adding names to IPs
IP_PTR_BLOCKLIST_RE = tuple()

# Statuses that devices must be to import
IMPORT_STATUS_ALLOWLIST = ("active",
                           "staged",
                           "failed",
                           "planned")

# Prefix of neighbor interfaces names from LLDP to be considered
SWITCH_INTERFACES_PREFIX_ALLOWLIST = ("et-",
                                      "xe-",
                                      "ge-")

# Hostname regexes that are immune to VIP removal because of a bug in provisioning them
# this is a temporary work around until 618766 is merged. The "VIP"s on these hosts will
# be given the netmask of the parent prefix.
NO_VIP_RE = (re.compile(r"^aqs.*"),
             re.compile(r"^restbase.*"),
             re.compile(r"^sessionstore.*"))

interface_ct = ContentType.objects.get_for_model(Interface)


class Importer:
    """This is shared functionality for interface and IP address importers."""

    @staticmethod
    def _get_ipv6_prefix_length(ipv6mask):
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
        """Perform the minor complexity of assigning an IP address to an interface as specified by
           a PuppetDB interface fact."""
        ipaddr_changed = False
        newdev_changed = False
        # heuristically determine if this is probably anycast
        if iface.startswith("lo:anycast"):
            self.log_info(f"{address} on {iface} is being assigned as anycast.")
            role = "anycast"
        else:
            role = ""

        # try to get the existing ip address object from netbox
        try:
            ipaddr = IPAddress.objects.get(address=str(address))
        except ObjectDoesNotExist:
            self.log_info(f"Creating {address}")
            ipaddr = IPAddress(address=str(address),
                               assigned_object=nbiface, role=role)
            ipaddr.save()

        if ipaddr.role in IPADDRESS_ROLES_NONUNIQUE:
            self.log_warning(f"Skipping assigning existing IP {address} with role {ipaddr.role} to {iface}. "
                             f"The IP might have the wrong netmask (expected /32 or /128 for VIP-like IPs)")

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
            self.log_info(f"Assigning {address} to {newdev}:{nbiface}")
        elif olddev != newdev:
            # the ip address is assigned to a completely different device
            # and this is not a vdev, reassign
            self.log_info(f"Taking IP address {ipaddr} from {olddev}:{ipaddr.assigned_object}")
            self.log_info(f"Assigning {address} to {newdev}:{nbiface}")
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
            self.log_info(f"Non-active IP address {ipaddr} being assigned, old status {ipaddr.status}")

        if is_primary:
            # Try assigning DNS name and getting information about DNS.
            if ipaddr.dns_name == networking["fqdn"]:
                self.log_info(f"{networking['fqdn']} assign_name: {ipaddr.address} already has correct DNS name.")
            elif ipaddr.dns_name:
                self.log_failure((f"{networking['fqdn']} assign_name: {ipaddr.address} has a different DNS name than"
                                  f"expected: {ipaddr.dns_name}"))

            if is_ipv6 and (newdev.primary_ip6 != ipaddr):
                ipaddr.is_primary = True
                ipaddr_changed = True
                newdev.primary_ip6 = ipaddr
                newdev_changed = True
                self.log_info(f"Setting {ipaddr} as primary for {newdev}")
            elif not is_ipv6 and (newdev.primary_ip4 != ipaddr):
                ipaddr.is_primary = True
                ipaddr_changed = True
                newdev.primary_ip4 = ipaddr
                newdev_changed = True
                self.log_info(f"Setting {ipaddr} as primary for {newdev}")
            else:
                self.log_info(f"{ipaddr} is already primary for {newdev}")

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

        if (vip_exempt):
            # FIXME
            # this is a bug in our deployment of certain servers where some service addresses have
            # an incorrect netmask and aren't actually VIPs
            # figure out the actual netmask from the prefix
            prefixq = PrefixFilterSet().search_contains(Prefix.objects.all(), "", str(address))
            if (not prefixq):
                self.log_failure(f"Can't find matching prefix for {address} when fixing netmask!")
                return None
            realnetmask = max([i.prefix.prefixlen for i in prefixq])
            address = ipaddress.ip_interface(f"{addr}/{realnetmask}")
            self.log_info("VIP exempt: Overriding provided netmask")

        if (is_anycast or (address.network.prefixlen in (32, 128))):
            self._handle_vip(address, is_anycast)
            return None

        return address

    def _handle_vip(self, address, is_anycast):
        """Do special processing for a potential VIP that will not be bound to an interface."""
        # Given a VIP, handle directly rather than processing with a host interface.
        role = "anycast" if is_anycast else "vip"
        try:
            ipaddrs = IPAddress.objects.filter(address=str(address))
            if (ipaddrs.count() > 1):
                self.log_debug(f"{address} has multiple results, taking the 0th one")
            elif (ipaddrs.count() == 0):
                raise ObjectDoesNotExist()
            ipaddr = ipaddrs[0]
            if ipaddr.role != role or ipaddr.assigned_object is not None or ipaddr.status != "active":
                ipaddr.role = role
                # We specially handle VIP addresses but do not allow them to be bound
                ipaddr.assigned_object = None
                ipaddr.status = "active"
                ipaddr.save()
                self.log_success(f"{address}: {role}, set to no interface and active")
        except ObjectDoesNotExist:
            self.log_success(f"{address}: created, {role}, no interface and active")
            ipaddr = IPAddress(address=str(address),
                               assigned_object=None, role=role,
                               status='active')
            ipaddr.save()

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

            iface_fmt = InterfaceTypeChoices.TYPE_1GE_FIXED  # Default to 1G
            if z_iface.startswith('xe-'):  # 10G start with xe-
                iface_fmt = InterfaceTypeChoices.TYPE_10GE_SFP_PLUS
            elif z_iface.startswith('et-'):  # If a server is et- it's 25G
                iface_fmt = InterfaceTypeChoices.TYPE_25GE_SFP28

            z_nbiface = Interface(name=z_iface,
                                  mgmt_only=False,
                                  device=z_nbdevice,
                                  type=iface_fmt,
                                  mtu=mtu)
            z_nbiface.save()
            self.log_success(f"{z_nbdevice}: created interface {z_iface}")
        return z_nbiface

    def _update_z_vlan(self, lldp_iface, z_nbiface):
        """Sets the proper vlan info on a remote LLDP interface when needed."""
        # Now update the port vlan config if needed
        mode = lldp_iface['vlans']['mode']
        if mode == 'tagged-all':
            mode = 'tagged'
        nb_tagged_vlans = []
        if 'tagged_vlans' in lldp_iface['vlans']:
            for vlan_tag in lldp_iface['vlans']['tagged_vlans']:
                # TODO unlikely to happen as we use unique access vlan VID (tag),
                # but this will fail if two vlans have the same VID (tag)
                nb_tagged_vlans.append(VLAN.objects.get(vid=vlan_tag))
        nb_untagged_vlan = None
        if 'untagged_vlan' in lldp_iface['vlans']:
            nb_untagged_vlan = VLAN.objects.get(vid=lldp_iface['vlans']['untagged_vlan'])

        changed = False
        if z_nbiface.mode != mode:
            z_nbiface.mode = mode
            changed = True
        if z_nbiface.untagged_vlan != nb_untagged_vlan:
            z_nbiface.untagged_vlan = nb_untagged_vlan
            changed = True
        if list(z_nbiface.tagged_vlans.all()) != nb_tagged_vlans:
            z_nbiface.tagged_vlans.set(nb_tagged_vlans)
            changed = True
        if changed:
            self.log_success(f"{z_nbiface.device}: updating vlans for interface {z_nbiface}")
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
                self.log_success(f"{nbiface.device}: Remove cable from {nbiface}")
                nbcable.delete()
                nbcable = None
            if z_nbcable is not None:
                self.log_success(f"{z_nbiface.device}: remove cable from {z_nbiface}")
                z_nbcable.delete()
                z_nbcable = None
        elif nbcable is not None:
            # If they match and are not None, we still need to check if the cable ID is good
            if label and nbcable.label != label:
                nbcable.label = label
                self.log_success(f"{nbiface.device}: update label for {nbcable}: {label}")
                nbcable.save()
        # Now we either have a fully correct cable, or nbcable == z_nbcable == None
        # In the 2nd case, we create the cable
        if nbcable is None:
            self._create_cable(nbiface, z_nbiface, label=label)

    def _make_interface_vm(self, device, iface, iface_dict, mtu):
        # only set MTU if it is non-default and not a loopback
        nbiface = VMInterface(name=iface,
                              virtual_machine=device,
                              mtu=mtu)
        nbiface.save()
        return nbiface

    def _make_interface(self, device, iface, iface_dict, net_driver, is_vdev, mtu):
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

    def _import_interfaces_for_device(self, device, net_driver, networking, lldp, is_vm=False):
        """Resolve one device's interfaces and ip addresses based on a net_driver, networking and lldp dictionary
           as would be obtained from PuppetDB under those key names."""
        output = []

        for device_interface in device.interfaces.all():
            # Clean up potential ##PRIMARY## interfaces
            if device_interface.name == '##PRIMARY##' and 'primary' in networking:
                device_interface.name = networking['primary']
                if ((not is_vm) and (net_driver[networking['primary']]["speed"] == 10000)):
                    device_interface.type = InterfaceTypeChoices.TYPE_10GE_SFP_PLUS
                device_interface.save()
                self.log_success(f"{device.name}: renamed ##PRIMARY## interface to {device_interface.name}")
        for iface, iface_dict in networking["interfaces"].items():
            is_vdev = ((":" in iface) or ("." in iface) or ("lo" == iface))
            is_anycast = (iface.startswith("lo:anycast"))
            if any(r.match(iface) for r in INTERFACE_IMPORT_BLOCKLIST_RE):
                # don't create interfaces for blocklisted iface, but we still want to process
                # their IP addresses.
                nbiface = None
            else:
                try:
                    nbiface = device.interfaces.get(name=iface)
                except ObjectDoesNotExist:
                    self.log_info(f"Creating interface {iface} for device {device}")
                    # only set MTU if it is non-default and not a loopback
                    mtu = None
                    if "mtu" in iface_dict and iface_dict["mtu"] != 1500 and iface != "lo":
                        mtu = iface_dict["mtu"]
                    if is_vm:
                        nbiface = self._make_interface_vm(device, iface, iface_dict, mtu)
                    else:
                        nbiface = self._make_interface(device, iface, iface_dict, net_driver, is_vdev, mtu)

            # FIXME /32 bug things here
            vipexempt = any([r.match(device.name) for r in NO_VIP_RE])
            # process ipv4 addresses
            for binding in iface_dict.get('bindings', []):
                address = self._process_binding_address(binding, False, is_anycast, (vipexempt and not is_vdev))
                if address is None:
                    continue
                if address in ipaddress.IPv4Network('192.168.0.0/16'):  # non-routed network, ignore it
                    continue
                is_primary = (iface == networking['primary'] and str(address.ip) == networking['ip'])
                self._assign_ip_to_interface(address, nbiface, networking, iface, is_primary, False)
            # process ipv6 addresses
            for binding in iface_dict.get('bindings6', []):
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

                # If possible, we create/update the vlans details
                if 'vlans' in lldp[iface]:
                    self._update_z_vlan(lldp[iface], z_nbiface)

                # Now we create or update the cable
                self._update_cable(lldp[iface], nbiface, z_nbiface)

        # Now we can clean up all of the interfaces that are no longer present in PuppetDB.
        for device_interface in device.interfaces.all():
            if (device_interface.name not in networking["interfaces"]
               and device_interface.name not in ("mgmt", "##PRIMARY##")):
                # clean up interface if there are no IPs assigned, and there are no caebles connected
                device_iface_ct = ContentType.objects.get_for_model(device_interface)
                ipcount = IPAddress.objects.filter(assigned_object_id=device_interface.id,
                                                   assigned_object_type=device_iface_ct).count()
                if ipcount == 0 and ((hasattr(device_interface, 'cable') and device_interface.cable is None)
                                     or hasattr(device_interface, 'virtual_machine')):
                    self.log_info(f"{device.name}: removing interface no longer in puppet {device_interface.name}")
                    device_interface.delete()
                else:
                    self.log_failure(f"{device.name}: We want to remove interface {device_interface.name}, however "
                                     "it still has a cable or IP address associated with it. "
                                     "See https://wikitech.wikimedia.org/wiki/Netbox#Would_like_to_remove_interface")
        return output

    def _validate_device(self, device):
        """Check if device is OK for import."""
        # Devices should be in the STATUS_ALLOWLIST to import
        if device.status not in IMPORT_STATUS_ALLOWLIST:
            self.log_failure(
                f"{device} has an inappropriate status (must be one of {IMPORT_STATUS_ALLOWLIST}): {device.status}"
            )
            return False

        return True

    def _validate_vm(self, device):
        """Check if the virtual machine is OK for import."""
        return True  # Try to import VMs in any state if the data is provided.

    def _create_cable(self, nbiface, z_nbiface, label=''):
        """Create a cable between two interfaces."""
        color = ''
        cable_type = ''
        color_human = ''
        # Most of our infra are either blue 1G copper, or black 10G DAC.
        # Exceptions are yellow fibers for longer distances like LVS, or special sites like ulsfo
        if nbiface.type == InterfaceTypeChoices.TYPE_1GE_FIXED:
            color = ColorChoices.COLOR_BLUE
            color_human = ColorChoices.as_dict()[color]
            cable_type = CableTypeChoices.TYPE_CAT5E
        elif nbiface.type in (InterfaceTypeChoices.TYPE_10GE_SFP_PLUS, InterfaceTypeChoices.TYPE_25GE_SFP28):
            color = ColorChoices.COLOR_BLACK
            color_human = ColorChoices.as_dict()[color]
            cable_type = CableTypeChoices.TYPE_DAC_PASSIVE

        cable = Cable(termination_a=nbiface,
                      termination_a_type=interface_ct,
                      termination_b=z_nbiface,
                      termination_b_type=interface_ct,
                      label=label,
                      color=color,
                      type=cable_type,
                      status=CableStatusChoices.STATUS_CONNECTED)
        cable.save()
        self.log_success(f"{nbiface.device}: created cable {cable}")
        self.log_warning(f"{nbiface.device}: assuming {color_human} {cable_type} because {nbiface.type}")

    def _update_z_iface(self, z_nbdevice, z_iface, vlan, type):
        """Create switch interface if needed and set vlan info."""
        try:
            # Try to find if the interface exists
            z_nbiface = z_nbdevice.interfaces.get(name=z_iface)
        except ObjectDoesNotExist:  # If interface doesn't exist: create it
            z_nbiface = Interface(name=z_iface,
                                  mgmt_only=False,
                                  device=z_nbdevice,
                                  type=type)
            z_nbiface.save()
            self.log_success(f"{z_nbdevice}: created interface {z_iface}.")

        # Then configure it
        z_nbiface.mode = 'access'
        z_nbiface.untagged_vlan = vlan
        z_nbiface.enabled = True
        z_nbiface.mtu = 9192
        z_nbiface.save()
        self.log_success(f"{z_nbiface.device}:{z_nbiface} configured vlan.")
        return z_nbiface


class ImportNetworkFacts(Script, Importer):
    class Meta:
        name = "Import Interfaces from a JSON blob"
        description = "Accept a JSON blob and resolve interface and IP address differences."
        commit_default = False

    device = StringVar(description="The device name to import interfaces and IP addresses for.",
                       label="Device")
    jsonblob = TextVar(description=("A JSON Dictionary with at least the `networking` key similar to what PuppetDB "
                                    "outputs. It may contain a `net_driver` key which specifies the speed of each"
                                    "interface, but the devices will take the default value if this is not specified."),
                       label="Facts JSON")
    statusoverride = BooleanVar(description=("Normally only hosts of specific status are considered for import, if "
                                             "this setting is set, the script will ignore the host's status."),
                                label="Status Override")

    def __init__(self, *args, **vargs):
        super().__init__(*args, **vargs)

    def _is_invalid_facts(self, facts):
        """We can very validate facts beyond this level, things will just explode if the facts are incorrect however."""
        if ("networking" not in facts):
            self.log_failure(f"Can't find `networking` in facts JSON."
                             f"Keys in blob are: {list(facts.keys())}")
            return True
        if ("net_driver" not in facts):
            self.log_warning("Can't find `net_driver` in facts JSON. Using default speed for all interfaces.")

    def run(self, data, commit):
        """Execute script as per Script interface."""
        facts = json.loads(data["jsonblob"])
        if self._is_invalid_facts(facts):
            return ""

        is_vm = False
        try:
            device = Device.objects.get(name=data["device"])
            if ((not data["statusoverride"]) and (not self._validate_device(device))):
                return ""
        except ObjectDoesNotExist:
            try:
                device = VirtualMachine.objects.get(name=data["device"])
                if ((not data["statusoverride"]) and (not self._validate_vm(device))):
                    return ""
                is_vm = True
            except ObjectDoesNotExist:
                self.log_failure(f"Not devices found by the name {data['device']}")
                return ""

        self.log_info(f"Processing device {device}")
        net_driver = {}
        if "net_driver" in facts:
            net_driver = facts["net_driver"]
        lldp = {}
        if "lldp" in facts:
            lldp = facts["lldp"]
        messages = self._import_interfaces_for_device(device, net_driver, facts["networking"], lldp, is_vm)
        self.log_info(f"{device} done.")

        return "\n".join(messages)


class ImportPuppetDB(Script, Importer):
    class Meta:
        name = "Import Interfaces, IPAddresses, Cables and switch ports from PuppetDB"
        description = "Access PuppetDB and resolve interface and IP address differences."
        commit_default = False

    device = StringVar(description="The device name(s) to import interface(s) for (space separated)",
                       label="Devices")

    def _validate_device(self, device):
        """Check if a device is OK to import from PuppetDB (overrides Importer's)"""
        if device.tenant:
            self.log_failure(f"{device} has non-null tenant {device.tenant} skipping.")
            return False
        return super()._validate_device(device)

    def _get_networking_facts(self, cfg, device):
        """Access PuppetDB for `networking`, `net_driver` and `lldp` facts."""
        # Get networking facts
        puppetdb_url = "/".join([cfg["puppetdb"]["url"], "v1/facts", "{}", device.name])
        response = requests.get(puppetdb_url.format("networking"), verify=cfg["puppetdb"]["ca_cert"])
        if response.status_code != 200:
            self.log_failure(f"Cannot retrieve PuppetDB `networking` facts about {device.name}")
            return None, None, None
        networking = response.json()
        # Get net_driver facts
        response = requests.get(puppetdb_url.format("net_driver"), verify=cfg["puppetdb"]["ca_cert"])
        if response.status_code != 200:
            self.log_failure(f"Cannot retrieve PuppetDB `net_driver` facts about {device.name}")
            return None, None, None
        net_driver = response.json()
        # Get lldp facts
        response = requests.get(puppetdb_url.format("lldp"), verify=cfg["puppetdb"]["ca_cert"])
        if response.status_code != 200:
            self.log_failure(f"Cannot retrieve PuppetDB `lldp` facts about {device.name}")
            return None, None, None
        lldp = response.json()
        return net_driver, networking, lldp

    def run(self, data, commit):
        """Execute script as per Script interface."""
        cfg = configparser.ConfigParser()
        cfg.read(CONFIGFILE)

        devices = Device.objects.filter(name__in=data["device"].split())
        vmdevices = VirtualMachine.objects.filter(name__in=data["device"].split())
        messages = []
        if not devices and not vmdevices:
            message = "No Netbox devices found for specified list."
            self.log_failure(message)
            return message

        for device in devices:
            self.log_info(f"Processing device {device}")
            if self._validate_device(device):
                net_driver, networking, lldp = self._get_networking_facts(cfg, device)
                if net_driver is None:
                    continue
                messages.extend(self._import_interfaces_for_device(device, net_driver, networking, lldp, False))
            self.log_info(f"{device} done.")
        for device in vmdevices:
            self.log_info(f"Processing virtual device {device}")
            if self._validate_vm(device):
                net_driver, networking, lldp = self._get_networking_facts(cfg, device)
                if net_driver is None:
                    continue
                messages.extend(self._import_interfaces_for_device(device, net_driver, networking, lldp, True))
            self.log_info(f"{device} done.")

        return "\n".join(messages)


MGMT_IFACE_NAME = "mgmt"
PRIMARY_IFACE_NAME = "##PRIMARY##"
VLAN_TYPES = (
    "",  # Default value
    "public",
    "private",
    "analytics",
    "cloud-hosts",
)
VLAN_POP_TYPES = ("public", "private")
FRACK_TENANT_SLUG = "fr-tech"

CSV_HEADERS = ('device',
               'z_nbdevice',
               'vlan',
               'vlan_type',
               'skip_ipv6_dns',
               'cassandra_instances',
               'z_iface',
               'cable_id')


def format_logs(logs):
    """Return all log messages properly formatted."""
    return "\n".join(
        "[{level}] {msg}".format(level=level, msg=message) for level, message in logs
    )


class ProvisionServerNetworkCSV(Script):

    class Meta:
        name = "Provision multiple servers network attributes from a CSV"
        description = ("More exactly: IPs, interfaces (including mgmt and switch), primary cable, vlan.")
        commit_default = False

    csv_file = FileVar(
        required=True,
        label="CSV import",
        description="Template and example on https://phabricator.wikimedia.org/F32411089"
    )

    def run(self, data, commit):
        reader = csv.DictReader(io.StringIO(data['csv_file'].read().decode('utf-8')))

        for row in reader:
            try:
                data = self._transform_csv(row)
            except csv.Error as e:
                self.log_failure(f"Error parsing row {reader.line_num}: {e}")
                continue
            if not data:
                # If any issue with the transform (eg. typoed host), ignore the row
                continue
            provision_script = ProvisionServerNetwork()
            provision_script.provision_server(data)
            self.log.extend(provision_script.log)
        return format_logs(self.log)

    def _transform_csv(self, row):
        "Transform the CSV fields to Netbox objects."

        for header in CSV_HEADERS:
            try:
                row[header]
            except KeyError:
                self.log_failure(f"CSV header {header} missing, skipping.")
                return
        # Ensure that no cells are missing, not empty cells, but missing cells
        if any(value is None for value in row.values()):
            self.log_failure(f"{row['device']}: missing CSV cells, skipping.")
            return
        try:
            row['device'] = Device.objects.get(name=row['device'])
        except ObjectDoesNotExist:
            self.log_failure(f"{row['device']}: device not found, skipping.")
            return
        try:
            row['z_nbdevice'] = Device.objects.get(name=row['z_nbdevice'])
        except ObjectDoesNotExist:
            self.log_failure(f"{row['device']}: switch {row['z_nbdevice']} not found, skipping.")
            return
        if row['vlan']:
            try:
                row['vlan'] = VLAN.objects.get(name=row['vlan'], site=row['device'].site)
            except ObjectDoesNotExist:
                self.log_failure(f"{row['device']}: vlan {row['vlan']} not found, skipping.")
                return
        row['skip_ipv6_dns'] = bool(int(row['skip_ipv6_dns']))
        if row['cassandra_instances']:
            row['cassandra_instances'] = int(row['cassandra_instances'])
        else:
            row['cassandra_instances'] = 0

        return row


class MoveServer(Script, Importer):
    class Meta:
        name = "Move a server within the same row"
        description = ("More exactly: keep the same vlan and IP.")
        commit_default = False

    device = ObjectVar(
        required=True,
        description=("Server. (Required)"),
        model=Device,
        query_params={
            'role': 'server',
        }
    )
    z_nbdevice = ObjectVar(
        required=True,
        label="New switch",
        description=("New top of rack switch. (Required)"),
        model=Device,
        query_params={
            'role': ('asw', 'cloudsw'),
            'status': ('active', 'staged'),
        }
    )
    z_iface = StringVar(label="Switch interface", description="Switch interface. (Required)", required=True)

    position = ChoiceVar(
        required=True,
        choices=[(i, i) for i in range(48)],
        label="New rack unit",
        description=("Rack will be the same as the new top of rack switch."),
    )
    cable_id = StringVar(label="Cable ID", required=False)

    def run(self, data, commit):
        """Run the script and return all the log messages."""
        self.log_info(f"Called with parameters: {data}")
        self.move_server(data)
        return format_logs(self.log)

    def move_server(self, data):
        """Process a single device."""
        device = data['device']
        z_nbdevice = data['z_nbdevice']
        z_iface = data['z_iface']
        position = data['position']
        cable_id = data['cable_id']

        if not z_nbdevice or z_iface == '':
            self.log_failure(
                f"{device}: New switch or switch interface missing, skipping."
            )
            return

        if z_nbdevice.status not in ('active', 'staged'):
            self.log_failure(f"{device}: switch {z_nbdevice} with status {z_nbdevice.status}, "
                             "expected Active or Staged, skipping.")
            return

        if int(position) == 0:
            self.log_failure(f"{device}: Rack unit can't be 0, skipping.")
            return

        if device.device_role.slug != "server":
            self.log_failure(
                f"{device.name}: role {device.device_role}, only servers are supported, skipping."
            )
            return

        if z_nbdevice.device_role.slug not in ('asw', 'cloudsw'):
            self.log_failure(f"{device}: switch {z_nbdevice} with role {z_nbdevice.device_role}, "
                             "only switches are supported, skipping.")
            return

        # find main interface
        ifaces_connected = device.interfaces.filter(mgmt_only=False).exclude(cable=None)
        if len(ifaces_connected) != 1:
            ifaces_list = ", ".join(i.name for i in ifaces_connected)
            self.log_failure(f"{device}: either 0 or more than 1 connected interface: {ifaces_list},"
                             f" please update Netbox manually, skipping.")
            return
        # At this point there is only the one.
        nbiface = ifaces_connected[0]
        nbcable = nbiface.cable
        # Find old switch interface, one one side or the other of the cable
        if nbcable.termination_a != nbiface:
            z_old_nbiface = nbcable.termination_a
        elif nbcable.termination_b != nbiface:
            z_old_nbiface = nbcable.termination_b

        # Configure the new switch interface
        z_nbiface = self._update_z_iface(z_nbdevice, z_iface, z_old_nbiface.untagged_vlan, z_old_nbiface.type)
        if z_nbiface.cable:
            self.log_failure(f"There is already a cable on {z_nbiface.device}:{z_nbiface} (typo?), skipping.")
            return

        # Clean the old one
        z_old_nbiface.enabled = False
        z_old_nbiface.mode = ''
        z_old_nbiface.untagged_vlan = None
        z_old_nbiface.mtu = None
        z_old_nbiface.tagged_vlans.set([])
        z_old_nbiface.save()
        self.log_success(f"{device}: reset old switch interface {z_old_nbiface.device}:{z_old_nbiface}.")

        # Remove the old cable
        nbcable.delete()
        self.log_success(f"{device}: deleted old cable.")

        # Create the new one
        self._create_cable(nbiface, z_nbiface, label=cable_id if cable_id else '')

        # Don't forget to update the device rack/U
        device.rack = z_nbdevice.rack
        device.position = int(position)
        device.save()
        self.log_success(f"{device}: moved to rack {device.rack}, U{device.position}.")


class ProvisionServerNetwork(Script, Importer):

    class Meta:
        name = "Provision a server's network attributes"
        description = ("More exactly: IPs, interfaces (including mgmt and switch), primary cable, vlan.")
        commit_default = False

    device = ObjectVar(
        required=True,
        description=("Inventory or planned server. (Required)"),
        model=Device,
        query_params={
            'role': 'server',
            'status': ('inventory', 'planned'),
        }
    )

    z_nbdevice = ObjectVar(
        required=True,
        label="Switch",
        description=("Top of rack switch. (Required)"),
        model=Device,
        query_params={
            'role': ('asw', 'cloudsw'),
            'status': ('active', 'staged'),
        }
    )

    z_iface = StringVar(label="Switch interface", description="Switch interface. (Required)", required=True)

    cable_id = StringVar(label="Cable ID", required=False)

    skip_ipv6_dns = BooleanVar(
        required=False,
        label="Skip IPv6 DNS records.",
        description=("Skip the generation of the IPv6 DNS records. Enable if the devices don't yet fully support "
                     "IPv6."),
    )
    cassandra_instances = ChoiceVar(
        required=False,
        choices=[(i, i) for i in range(6)],
        label="How many Cassandra instances",
        description=("To be set only for hosts that will run Cassandra. This many additional IPv4s will be "
                     "allocated and their DNS name will be set to $HOSTNAME-a, $HOSTNAME-b, etc."),
    )
    vlan_type = ChoiceVar(
        required=False,
        choices=[(value, value if value else "-" * 9) for value in VLAN_TYPES],
        label="VLAN Type",
        description=("The VLAN type to use for assigning the primary IPs. The specific VLAN will be automatically "
                     "chosen based on the device. For not yet supported cases use the VLAN parameter below. The "
                     "VLAN Type and VLAN parameters are mutually exclusive."),
    )
    vlan = ObjectVar(
        required=False,
        label="VLAN",
        description=("Select the specific VLAN if the VLAN Type parameter doesn't support the device's VLAN. The "
                     "VLAN Type and VLAN parameters are mutually exclusive."),
        model=VLAN,
        query_params={
            "group": "production",
            "status": "active",
            "name__nisw": [f"{vlan}{i}-" for vlan in VLAN_TYPES if vlan for i in (1, 2)],
        }
    )

    def run(self, data, commit):
        """Run the script and return all the log messages."""
        self.log_info(f"Called with parameters: {data}")
        self.provision_server(data)
        return format_logs(self.log)

    def provision_server(self, data):
        """Process a single device."""
        device = data['device']
        z_nbdevice = data['z_nbdevice']
        z_iface = data['z_iface']
        cable_id = data['cable_id']
        assign_mgmt = True

        if not data["vlan_type"] and not data["vlan"]:
            self.log_failure(f"{device}: one parameter between VLAN Type and VLAN must be specified, skipping.")
            return

        if data["vlan_type"] and data["vlan"]:
            self.log_failure(f"{device}: only one parameter between VLAN Type and VLAN can be specified, skipping.")
            return

        if device.status not in ("inventory", "planned"):
            self.log_failure(
                f"{device}: status {device.status}, expected Inventory or Planned, skipping."
            )
            return

        if not z_nbdevice or z_iface == '':
            self.log_failure(
                f"{device}: switch or switch interface missing, skipping."
            )
            return

        if z_nbdevice.status not in ('active', 'staged'):
            self.log_failure(f"{device}: switch {z_nbdevice} with status {z_nbdevice.status}, "
                             "expected Active or Staged, skipping.")
            return

        if not device.rack:
            self.log_failure(f"{device}: missing rack information, skipping.")
            return

        if device.device_role.slug != "server":
            self.log_failure(
                f"{device.name}: role {device.device_role}, only servers are supported, skipping."
            )
            return

        if z_nbdevice.device_role.slug not in ('asw', 'cloudsw'):
            self.log_failure(f"{device}: switch {z_nbdevice} with role {z_nbdevice.device_role}, "
                             "only switches are supported, skipping.")
            return

        ifaces = device.interfaces.all()
        #  If the device have interface(s)
        if ifaces:
            # But it's only the mgmt, continue with creating the primary
            if (len(ifaces) == 1 and ifaces[0].name == MGMT_IFACE_NAME and ifaces[0].count_ipaddresses == 1
                    and ifaces[0].ip_addresses.all()[0].dns_name):
                self.log_warning(f"{device}: Skipping assignment of MGMT interface because already allocated")
                assign_mgmt = False
            else:
                # All the interfaces exist (mgmt & revenue), don't go further
                ifaces_list = ", ".join(i.name for i in ifaces)
                self.log_failure(f"{device}: interfaces already defined: {ifaces_list}, skipping.")
                return

        # Assigning first the primary IPs as it can fail some validation step
        if data["vlan_type"]:
            vlan = self._get_vlan(data["vlan_type"], device)
            if vlan is None:
                return
        else:
            vlan = data["vlan"]

        if not self._is_vlan_valid(vlan, device):
            return

        iface_fmt = InterfaceTypeChoices.TYPE_1GE_FIXED  # Default to 1G
        if z_iface.startswith('xe-'):  # 10G start with xe-
            iface_fmt = InterfaceTypeChoices.TYPE_10GE_SFP_PLUS
        elif z_iface.startswith('et-'):  # If a server is et- it's 25G
            iface_fmt = InterfaceTypeChoices.TYPE_25GE_SFP28

        if device.tenant is not None and device.tenant.slug == FRACK_TENANT_SLUG:
            self.log_warning(f"{device}: Skipping Primary IP allocation with tenant {device.tenant}. "
                             "Primary IP allocation for Fundraising Tech is done manually in the DNS repository.")
        else:
            nbiface = self._assign_primary(device, vlan, iface_type=iface_fmt, skip_ipv6_dns=data["skip_ipv6_dns"],
                                           cassandra_instances=int(data["cassandra_instances"]))

            # Now that we're done with the primary interface, we tackle the switch side
            z_nbiface = self._update_z_iface(z_nbdevice, z_iface, vlan, iface_fmt)

            # And now the cable between the two
            # If the switch port already have a cable, we don't try to delete it
            if z_nbiface.cable:
                self.log_warning(f"There is already a cable on {z_nbiface.device}:{z_nbiface} (typo?), "
                                 f"Skipping cable creation, please do it manually")
                return
            self._create_cable(nbiface, z_nbiface, label=cable_id if cable_id else '')

        if assign_mgmt:
            self._assign_mgmt(device)

    def _assign_mgmt(self, device):
        """Create a management interface in the device and assign to it a management IP."""
        iface_type = InterfaceTypeChoices.TYPE_1GE_FIXED
        iface = self._add_iface(MGMT_IFACE_NAME, device, iface_type=iface_type, mgmt=True)

        # determine prefix appropriate to site of device
        try:
            prefix = Prefix.objects.get(
                site=device.site, role__slug="management", tenant=device.tenant, status="active"
            )
        except ObjectDoesNotExist:
            self.log_failure(f"{device}: can't find management prefix for site {device.site.slug}.")
            return

        self.log_debug(f"{device}: selecting address from prefix {prefix.prefix}")
        ip_address = prefix.get_first_available_ip()
        if ip_address is None:
            self.log_failure(f"{device}: unable to find an available IP in prefix {prefix.prefix}")
            return

        if device.tenant and device.tenant.slug == FRACK_TENANT_SLUG:
            dns_name = f"{device.name}.mgmt.frack.{device.site.slug}.wmnet"
        else:
            dns_name = f"{device.name}.mgmt.{device.site.slug}.wmnet"

        self._add_ip(ip_address, dns_name, prefix, iface, device)

    def _assign_primary(self, device, vlan, *, iface_type, skip_ipv6_dns=False, cassandra_instances=0):
        """Create a primary interface in the device and assign to it an IPv4, a mapped IPv6 and related DNS records.

        If Cassandra instances is greater than zero allocate additional IPs for those with hostname
        $HOSTNAME-a, $HOSTNAME-b, etc.

        """
        # We create the interface so IP assignment doesn't impact the physical layer
        iface = self._add_iface(PRIMARY_IFACE_NAME, device, iface_type=iface_type, mgmt=False)

        prefixes_v4 = vlan.prefixes.filter(prefix__family=4, status="active")  # Must always be one
        prefixes_v6 = vlan.prefixes.filter(prefix__family=6, status="active")  # Can either be one or not exists
        if len(prefixes_v4) != 1 or len(prefixes_v6) > 1:
            self.log_warning(f"{device}: unsupported case, found {len(prefixes_v4)} v4 prefixes and "
                             f"{len(prefixes_v6)} v6 prefixes, expected 1 and 0 or 1 respectively, "
                             "skipping IP allocation.")
            return iface

        prefix_v4 = prefixes_v4[0]
        prefix_v6 = None
        if prefixes_v6:
            prefix_v6 = prefixes_v6[0]

        self.log_debug(f"{device}: selecting address from prefix {prefix_v4.prefix}")

        ip_address = prefix_v4.get_first_available_ip()
        if ip_address is None:
            self.log_warning(f"{device}: unable to find an available IP in prefix {prefix_v4.prefix}, "
                             "skipping IP allocation.")
            return iface

        if prefix_v4.prefix.is_private():
            if device.tenant and device.tenant.slug == FRACK_TENANT_SLUG:
                dns_suffix = f"frack.{device.site.slug}.wmnet"
            else:
                dns_suffix = f"{device.site.slug}.wmnet"
        else:
            dns_suffix = "wikimedia.org"

        dns_name = f"{device.name}.{dns_suffix}"
        ip_v4 = self._add_ip(ip_address, dns_name, prefix_v4, iface, device)
        device.primary_ip4 = ip_v4
        device.save()
        self.log_success(f"{device}: marked IPv4 address {ip_v4} as primary IPv4 for device.")

        # Allocate additional IPs
        for letter in ascii_lowercase[:cassandra_instances]:
            extra_ip_address = prefix_v4.get_first_available_ip()
            extra_dns_name = f"{device.name}-{letter}.{dns_suffix}"
            self._add_ip(extra_ip_address, extra_dns_name, prefix_v4, iface, device)

        if prefix_v6 is None:
            self.log_warning(f"{device}: no IPv6 prefix found for VLAN {vlan.name}, skipping IPv6 allocation.")
            # Whatever happen, as long as the interface is created, return it
            return iface

        dns_name_v6 = dns_name
        if skip_ipv6_dns:
            self.log_info(f"{device}: Not assigning DNS name to the IPv6 address as requested.")
            dns_name_v6 = ""

        # Generate the IPv6 address embedding the IPv4 address, for example from an IPv4 address 10.0.0.1 and an
        # IPv6 prefix 2001:db8:3c4d:15::/64 the mapped IPv6 address 2001:db8:3c4d:15:10:0:0:1/64 is generated.
        prefix_v6_base, prefix_v6_mask = str(prefix_v6).split("/")
        mapped_v4 = str(ip_v4).split('/')[0].replace(".", ":")
        ipv6_address = f"{prefix_v6_base.rstrip(':')}:{mapped_v4}/{prefix_v6_mask}"
        ip_v6 = self._add_ip(ipv6_address, dns_name_v6, prefix_v6, iface, device)
        device.primary_ip6 = ip_v6
        device.save()
        self.log_success(f"{device}: marked IPv6 address {ip_v6} as primary IPv6.")

        # Whatever happen, as long as the interface is created, return it
        return iface

    def _get_vlan(self, vlan_type, device):
        """Find and return the appropriate VLAN that matches the type and device location."""
        new_vlan_name = f"{vlan_type}1-{device.rack.name.lower()}-{device.site.slug}"

        if device.site.slug in ("eqiad", "codfw"):
            # TODO: add support for additional VLANs of a given type (e.g. private2)
            if vlan_type == 'cloud-hosts':
                old_vlan_name = f"cloud-hosts1-{device.site.slug}"
            else:
                old_vlan_name = f"{vlan_type}1-{device.rack.group.slug.split('-')[-1]}-{device.site.slug}"
        else:
            if vlan_type not in VLAN_POP_TYPES:
                self.log_failure(f"{device}: VLAN type {vlan_type} not available in site {device.site.slug}, skipping.")
                return

            old_vlan_name = f"{vlan_type}1-{device.site.slug}"

        try:
            return VLAN.objects.get(name=old_vlan_name, status="active")
        except ObjectDoesNotExist:
            try:
                return VLAN.objects.get(name=new_vlan_name, status="active")
            except ObjectDoesNotExist:
                self.log_failure(
                    f"{device}: unable to find VLAN with name {old_vlan_name} or {new_vlan_name}, skipping.")

    def _is_vlan_valid(self, vlan, device):
        """Try to ensure that the VLAN matches the device location."""
        if vlan.site != device.site:
            self.log_failure(
                f"{device}: mismatch site for VLAN {vlan.name}: "
                f"{device.site.slug} (device) != {vlan.site.slug} (VLAN), skipping."
            )
            return False

        if vlan.tenant != device.tenant:
            self.log_failure(
                f"{device}: , mismatch tenant for VLAN {vlan.name}: "
                f"{device.tenant} (device) != {vlan.tenant} (VLAN), skipping."
            )
            return False

        # Attempt to validate the row for old vlan names, for the new names the vlans are per-row
        devices = {i.device for i in vlan.get_interfaces()}
        if not devices:  # This is the first device of a new VLAN, can't validate it
            return True

        racks = {dev.rack for dev in devices}
        rack_groups = {rack.group for rack in racks}
        if device.rack.group not in rack_groups:
            self.log_failure(f"{device} is in row {device.rack.group} but VLAN {vlan.name} is present only in "
                             f"{rack_groups}. Skipping device because of invalid VLAN.")
            return False

        if device.rack not in racks:
            self.log_warning(f"{device} is the first device in rack {device.rack} to be added to VLAN {vlan.name}, "
                             f"unable to automatically verify if that's correct, please double check.")

        return True

    def _add_iface(self, name, device, *, iface_type, mgmt=False):
        """Add an interface to the device."""
        iface = Interface(name=name, mgmt_only=mgmt, device=device, type=iface_type)
        iface.save()
        self.log_success(f"{device}: created interface {name} (mgmt={mgmt})")
        return iface

    def _add_ip(self, address, dns_name, prefix, iface, device):
        """Assign an IP address to the interface."""
        address = IPAddress(
            address=address,
            status="active",
            dns_name=dns_name,
            vrf=prefix.vrf.pk if prefix.vrf else None,
            assigned_object=iface,
            tenant=device.tenant,
        )
        address.save()
        self.log_success(f"{device}: assigned IPv{prefix.family} {address} to interface {iface.name} "
                         f"with DNS name '{dns_name}'.")

        return address
