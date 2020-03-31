import configparser
import ipaddress
import re
import json

import requests

from dns import resolver, reversename
from dns.exception import DNSException

from string import ascii_lowercase

from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q

from dcim.choices import InterfaceTypeChoices
from dcim.models import Device, Interface
from extras.constants import LOG_LEVEL_CODES
from extras.scripts import BooleanVar, ChoiceVar, ObjectVar, Script, StringVar, TextVar
from ipam.models import IPAddress, Prefix, VLAN
from ipam.filters import PrefixFilterSet
from utilities.forms import APISelect
from virtualization.models import VirtualMachine

CONFIGFILE = "/etc/netbox/reports.cfg"

# Interfaces which we skip when importing
INTERFACE_IMPORT_BLACKLIST_RE = (re.compile(r"^cali.*"),  # Kubernetes
                                 re.compile(r"^tap.*"),  # Ganeti & Openstack
                                 re.compile(r"^lo$"),)  # Loopback

# PTRs that we skip when adding names to IPs
IP_PTR_BLACKLIST_RE = tuple()

# Statuses that devices must be to import
IMPORT_STATUS_WHITELIST = ("active",
                           "staged",
                           "failed",
                           "planned")

# Hostname regexes that are immune to VIP removal because of a bug in provisioning them
# this is a temporary work around until 618766 is merged. The "VIP"s on these hosts will
# be given the netmask of the parent prefix.
NO_VIP_RE = (re.compile(r"^aqs.*"),
             re.compile(r"^restbase.*"),
             re.compile(r"^sessionstore.*"))


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

    def _resolve_address(self, qname, rrtype):
        """Perform a DNS resolution on an A or AAAA record.

        Returns empty list on no results.
        """
        results = []
        try:
            result = resolver.query(qname, rrtype)
            for res in result.rrset:
                results.append(res.address)
        except (resolver.NoAnswer, resolver.NXDOMAIN):
            self.log_debug(f"[DNS] Record {rrtype} not found for {qname}")
        except DNSException:
            self.log_debug(f"[DNS] Cannot resolve {rrtype} for {qname}")
        return results

    def _resolve_ipv6(self, dnsname):
        return self._resolve_address(dnsname, "AAAA")

    def _resolve_ipv4(self, dnsname):
        return self._resolve_address(dnsname, "A")

    def _resolve_ptr(self, ipaddr):
        """Perform a DNS PTR resolution.

        Returns empty None if there is no result."""
        try:
            result = resolver.query(reversename.from_address(ipaddr), "PTR")
            results = [r.target.to_text().strip(".") for r in result.rrset]
            return results
        except (resolver.NoAnswer, resolver.NXDOMAIN):
            self.log_debug(f"[DNS] PTR record not found for {ipaddr}")
        except DNSException as e:
            self.log_debug(f"[DNS] PTR cannot resolve {ipaddr}: exception {e}")
        return []

    def _assign_name(self, ipaddr, networking, is_ipv6):
        """Possibly assign name to address if the conditions are right. Otherwise,
           return a message array explaining why we didn't."""

        # leave it alone if it's already assigned to the right name
        if (ipaddr.dns_name == networking["fqdn"]):
            self.log_info(f"{networking['fqdn']} assign_name: {ipaddr.address} already has correct DNS name.")
            return []

        # leave it alone if it's assigned another name, but warn as this requires human intervention
        if (ipaddr.dns_name):
            self.log_failure((f"{networking['fqdn']} assign_name: {ipaddr.address} has a different DNS name than"
                              f"expected: {ipaddr.dns_name}"))
            return []

        # consider ipaddress for DNS name
        # FIXME: Note that the DNS logic is transition period
        # temporary to shake out any unassigned IP addresses and similar.
        output = []
        nogo = True
        ptr = self._resolve_ptr(str(ipaddress.ip_interface(ipaddr.address).ip))
        if (is_ipv6):
            ipv6 = self._resolve_ipv6(networking["fqdn"])
            if (not ipv6) and (not ptr):
                self.log_warning(f"{networking['fqdn']} assign_name: No IPv6 DNS records.")
                output.append(f"{networking['fqdn']} assign_name: No IPv6 DNS records.")
            elif (not ipv6):
                self.log_warning(f"{networking['fqdn']} assign_name: No IPv6 AAAA records.")
                output.append(f"{networking['fqdn']} assign_name: No IPv6 AAAA records.")
            elif (not ptr):
                self.log_warning(f"{networking['fqdn']} assign_name: No IPv6 PTR record.")
                output.append(f"{networking['fqdn']} assign_name: No IPv6 PTR record.")
            else:
                nogo = False
        else:
            ipv4 = self._resolve_ipv4(networking["fqdn"])
            if (not ipv4) and (not ptr):
                self.log_warning(f"{networking['fqdn']} assign_name: No IPv4 DNS records.")
                output.append(f"{networking['fqdn']} assign_name: No IPv4 DNS records.")
            elif (not ipv4):
                self.log_warning(f"{networking['fqdn']} assign_name: No IPv4 A records.")
                output.append(f"{networking['fqdn']} assign_name: No IPv4 A records.")
            elif (not ptr):
                self.log_warning(f"{networking['fqdn']} assign_name: No IPv4 PTR record.")
                output.append(f"{networking['fqdn']} assign_name: No IPv4 PTR record.")
            else:
                nogo = False

        if not nogo:
            self.log_info(f"Adding FQDN {networking['fqdn']} to {ipaddr}")
            ipaddr.dns_name = networking["fqdn"]

        return output

    def _maybe_assign_rdns(self, ipaddr):
        ptr = self._resolve_ptr(str(ipaddress.ip_interface(ipaddr.address).ip))

        if ptr:
            if (len(ptr) > 1):
                self.log_error(f"SKIPPING assignment for {ipaddr} has more than 1 reverse value.")
                return
            potname = ptr[0]
            if any(r.match(potname) for r in IP_PTR_BLACKLIST_RE):
                self.log_warning(f"SKIPPING assignment for {ipaddr} has blacklisted name {potname}.")
                return
            self.log_info(f"assigning ptr name {potname} to {ipaddr}")
            ipaddr.dns_name = potname

    def _assign_ip_to_interface(self, address, nbiface, networking, iface, is_primary, is_ipv6):
        """Perform the minor complexity of assigning an IP address to an interface as specified by
           a PuppetDB interface fact."""
        output = []

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
                               interface=nbiface, role=role)
            ipaddr.save()

        oldiface = ipaddr.interface
        if oldiface:
            if ipaddr.interface.virtual_machine:
                olddev = ipaddr.interface.virtual_machine
            else:
                olddev = ipaddr.interface.device
        else:
            olddev = None

        if nbiface.virtual_machine:
            newdev = nbiface.virtual_machine
        else:
            newdev = nbiface.device

        if not ipaddr.interface:
            # no interface assigned
            self.log_info(f"Assigning {address} to {newdev}:{nbiface}")
        elif olddev != newdev:
            # the ip address is asigned to a completely different device
            # and this is not a vdev, reassign
            self.log_info(f"Taking IP address {ipaddr} from {olddev}:{ipaddr.interface}")
            self.log_info(f"Assigning {address} to {newdev}:{nbiface}")
            if is_ipv6 and olddev.primary_ip6 == ipaddr:
                olddev.primary_ip6 = None
            elif olddev.primary_ip4 == ipaddr:
                olddev.primary_ip4 = None
            ipaddr.interface.save()
            olddev.save()
            ipaddr.save()
        else:
            # on same device but different interface
            if ipaddr.interface.name not in networking["interfaces"]:
                # basically renaming a device so we need to copy the description field
                nbiface.description = ipaddr.interface.description
                nbiface.save()

        # finally actually reassign interface
        ipaddr.interface = nbiface
        if ipaddr.status != "active" or ipaddr.status is None:
            self.log_info(f"Non-active IP address {ipaddr} being assigned, old status {ipaddr.status}")
        ipaddr.status = "active"

        if ipaddr.description == "reserved for infra":
            ipaddr.description = ""

        if (iface == networking["primary"] and is_primary):
            # Try assigning DNS name and getting information about DNS.
            output = self._assign_name(ipaddr, networking, is_ipv6)

            ipaddr.is_primary = True
            self.log_info(f"Setting {nbiface} as primary for {newdev}")
            if is_ipv6:
                newdev.primary_ip6 = ipaddr
            else:
                newdev.primary_ip4 = ipaddr
        else:
            # FIXME this is transitional and should be removed after dns is generated
            self._maybe_assign_rdns(ipaddr)

        newdev.save()

        ipaddr.role = role
        ipaddr.save()
        return output

    def _process_binding_address(self, binding, is_ipv6, is_anycast, vip_exempt):
        """Convert a binding to an ipaddress.ip_interface object, possibly pushing it to VIP processing
           (instead of being considered for attaching to an interface). Returns None if VIP, or an
           ipaddress.ip_interface object."""
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

        if (vip_exempt):
            # FIXME
            # this is a bug in our deployment of certain servers where some service addresses have
            # an incorrect netmask and aren't actually VIPs
            # figure out the actual netmask from the prefix
            prefixq = PrefixFilterSet().search_contains(Prefix.objects.all(), "", str(address))
            if (not prefixq):
                self.log_error(f"Can't find matching prefix for {address} when fixing netmask!")
                return None
            realnetmask = max([i.prefix.prefixlen for i in prefixq])
            address = ipaddress.ip_interface(f"{addr}/{realnetmask}")
            self.log_info("VIP exempt: Overriding provided netmask")

        if (is_anycast or (address.network.prefixlen in (32, 128))):
            # We specially handle VIP addresses but do not allow them to be bound
            self.log_info(f"{address} is a VIP and will be created but left unassigned.")
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
                self.log_info(f"{address} has multiple results ! taking the 0th one")
            elif (ipaddrs.count() == 0):
                raise ObjectDoesNotExist()
            ipaddr = ipaddrs[0]
            ipaddr.role = role
            ipaddr.interface = None
        except ObjectDoesNotExist:
            self.log_info(f"Creating {address}")
            ipaddr = IPAddress(address=str(address),
                               interface=None, role=role)
        ipaddr.status = "active"
        self._maybe_assign_rdns(ipaddr)
        ipaddr.save()

    def _import_interfaces_for_device(self, device, net_driver, networking, is_virtual=False):
        """Resolve one device's interfaces and ip addresses based on a net_driver and networking dictionary
           as would be obtained from PuppetDB under those key names."""
        output = []

        # clean up potential ##PRIMARY## interface
        for dif in device.interfaces.all():
            if dif.name == '##PRIMARY##' and 'primary' in networking:
                self.log_info(f"{device.name} Renaming ##PRIMARY## interface to {networking['primary']}")
                dif.name = networking['primary']
                dif.save()
                break

        for iface, iface_dict in networking["interfaces"].items():
            is_vdev = ((":" in iface) or ("." in iface) or ("lo" == iface))
            is_anycast = (iface.startswith("lo:anycast"))
            if any(r.match(iface) for r in INTERFACE_IMPORT_BLACKLIST_RE):
                # don't create interfaces for blacklisted iface, but we still want to process
                # their IP addresses.
                nbiface = None
            else:
                try:
                    nbiface = device.interfaces.get(name=iface)
                except ObjectDoesNotExist:
                    self.log_info(f"Creating interface {iface} for device {device}".format(iface, device))

                    iface_fmt = InterfaceTypeChoices.TYPE_1GE_FIXED

                    # heuristically determine the device format
                    if is_vdev or is_virtual:
                        iface_fmt = InterfaceTypeChoices.TYPE_VIRTUAL
                    elif iface in net_driver:
                        if net_driver[iface]["speed"] == 10000:
                            iface_fmt = InterfaceTypeChoices.TYPE_10GE_SFP_PLUS

                    # only set MTU if it is non-default and not a loopback
                    mtu = None
                    if "mtu" in iface_dict and iface_dict["mtu"] != 1500 and iface != "lo":
                        mtu = iface_dict["mtu"]

                    if is_virtual:
                        nbiface = Interface(name=iface,
                                            mgmt_only=False,
                                            virtual_machine=device,
                                            type=iface_fmt,
                                            mtu=mtu)
                    else:
                        nbiface = Interface(name=iface,
                                            mgmt_only=False,
                                            device=device,
                                            type=iface_fmt,
                                            mtu=mtu)
                    nbiface.save()

            # FIXME /32 bug things here
            vipexempt = any([r.match(device.name) for r in NO_VIP_RE])
            if "bindings" in iface_dict:
                for binding in iface_dict["bindings"]:
                    address = self._process_binding_address(binding, False, is_anycast, (vipexempt and not is_vdev))
                    if address is None or nbiface is None:
                        continue
                    # process ipv4 addresses
                    isprimary = False
                    if "ip" in iface_dict and binding["address"] == iface_dict["ip"]:
                        isprimary = True
                    output = output + self._assign_ip_to_interface(address,
                                                                   nbiface,
                                                                   networking,
                                                                   iface,
                                                                   isprimary,
                                                                   False)
            if "bindings6" in iface_dict:
                for binding in iface_dict["bindings6"]:
                    address = self._process_binding_address(binding, True, is_anycast, (vipexempt and not is_vdev))
                    if address is None or nbiface is None:
                        continue
                    # process ipv4 addresses
                    isprimary = False
                    if "ip" in iface_dict and binding["address"] == iface_dict["ip6"]:
                        isprimary = True
                    output = output + self._assign_ip_to_interface(address,
                                                                   nbiface,
                                                                   networking,
                                                                   iface,
                                                                   isprimary,
                                                                   True)
        return output

    def _validate_device(self, device):
        """Check if device is OK for import."""
        # Devices should be in the STATUS_WHITELIST to import
        if device.status not in IMPORT_STATUS_WHITELIST:
            self.log_failure(
                f"{device} has an inappropriate status (must be one of {IMPORT_STATUS_WHITELIST}): {device.status}"
            )
            return False

        return True

    def _validate_vm(self, device):
        """Check if the virtual machine is OK for import."""
        return True  # Try to import VMs in any state if the data is provided.


class ImportNetworkFacts(Script, Importer):
    class Meta:
        name = "Import Interfaces from a JSON blob"
        description = "Accept a JSON blob and resolve interface and IP address differences."

    device = StringVar(description="The device name to import interfaces and IP addresses for.",
                       label="Device")
    jsonblob = TextVar(description=("A JSON Dictionary with at least the `networking` key similar to what PuppetDB "
                                    "outputs. It may contain a `net_driver` key which specifies the speed of each"
                                    "interface, but the devices will take the default value if this is not specified."),
                       label="Facts JSON")
    statusoverride = BooleanVar(description="Override device status")

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
        messages = self._import_interfaces_for_device(device, net_driver, facts["networking"], is_vm)
        self.log_info(f"{device} done.")

        return "\n".join(messages)


class ImportPuppetDB(Script, Importer):
    class Meta:
        name = "Import Interfaces and IPAddresses from PuppetDB"
        description = "Access PuppetDB and resolve interface and IP address differences."

    device = StringVar(description="The device name(s) to import interface(s) for (space separated)",
                       label="Devices")

    def _validate_device(self, device):
        """Check if a device is OK to import from PuppetDB (overrides Importer's)"""
        if device.tenant:
            self.log_failure(f"{device} has non-null tenant {device.tenant} skipping.")
            return False
        return super()._validate_device(device)

    def _get_networking_facts(self, cfg, device):
        """Access PuppetDB for `networking` and `net_driver` facts."""
        # Get networking facts
        puppetdb_url = "/".join([cfg["puppetdb"]["url"], "v1/facts", "{}", device.name])
        response = requests.get(puppetdb_url.format("networking"), verify=cfg["puppetdb"]["ca_cert"])
        if response.status_code != 200:
            self.log_failure(f"Cannot retrieve PuppetDB `networking` facts about {device.name}")
            return None, None
        networking = response.json()
        # Get net_driver facts
        response = requests.get(puppetdb_url.format("net_driver"), verify=cfg["puppetdb"]["ca_cert"])
        if response.status_code != 200:
            self.log_failure(f"Cannot retrieve PuppetDB `net_driver` facts about {device.name}")
            return None, None
        net_driver = response.json()
        return net_driver, networking

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
                net_driver, networking = self._get_networking_facts(cfg, device)
                if net_driver is None:
                    continue
                messages.extend(self._import_interfaces_for_device(device, net_driver, networking, False))
            self.log_info(f"{device} done.")
        for device in vmdevices:
            self.log_info(f"Processing virtual device {device}")
            if self._validate_vm(device):
                net_driver, networking = self._get_networking_facts(cfg, device)
                if net_driver is None:
                    continue
                messages.extend(self._import_interfaces_for_device(device, net_driver, networking, True))
            self.log_info(f"{device} done.")

        return "\n".join(messages)


# Switch to True once all primary IPs are imported into Netbox
PRIMARY_IPS_ENABLED = False
MIGRATED_PRIMARY_SITES = ()
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
VLAN_QUERY_FILTERS = [~Q(name__istartswith=f"{i}1-") for i in VLAN_TYPES if i]
FRACK_TENANT_SLUG = "fr-tech"


class AssignIPs(Script):

    class Meta:
        name = "Add interfaces and IPs to devices"
        description = ("Create a management and primary interface for the specified device(s) and assign them the"
                       "necessary IP addresses.")

    devices = StringVar(
        label="Device(s)",
        description="Device name(s), space separated if more than one",
    )

    if PRIMARY_IPS_ENABLED:  # Temporary to hide unnecessary parameters at the moment
        skip_ipv6_dns = BooleanVar(
            label="Skip IPv6 DNS records",
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
            queryset=VLAN.objects.filter(*VLAN_QUERY_FILTERS, status="active", group__name="production"),
            widget=APISelect(
                api_url="/api/ipam/vlans/",
                display_field="name",
                additional_query_params={
                    "group": "production",
                    "name__nisw": [f"{i}1-" for i in VLAN_TYPES if i],
                }
            ),
        )

    def run(self, data):
        """Run the script and return all the log messages."""
        self.log_info(f"Called with parameters: {data}")
        self._run_script(data)
        return self._format_logs()

    def _run_script(self, data):
        """Run the script."""
        if PRIMARY_IPS_ENABLED and not data["vlan_type"] and not data["vlan"]:
            self.log_failure("One parameter between VLAN Type and VLAN must be specified, aborting.")
            return
        if PRIMARY_IPS_ENABLED and data["vlan_type"] and data["vlan"]:
            self.log_failure("Only one parameter between VLAN Type and VLAN can be specified, aborting.")
            return

        devices = Device.objects.filter(name__in=data["devices"].split())  # Additional checks performed below
        if not devices:
            self.log_failure(f"No devices found for: {data['devices']}.")
            return

        for device in devices:
            self._process_device(device, data)

    def _process_device(self, device, data):
        """Process a single device."""
        self.log_info(f"Processing device {device.name}")
        if device.status not in ("inventory", "planned"):
            self.log_failure(
                f"Skipping device {device.name} with status {device.status}, expected Inventory or Planned."
            )
            return

        if not device.rack:
            self.log_failure(f"Skipping device {device.name}, missing rack information.")
            return

        if device.device_role.slug != "server":
            self.log_failure(
                f"Skipping device {device.name} with role {device.device_role}, only servers are supported."
            )
            return

        ifaces = device.interfaces.all()
        if ifaces:
            ifaces_list = ", ".join(i.name for i in ifaces)
            self.log_failure(f"Skipping device {device.name}, interfaces already defined: {ifaces_list}")
            return

        # Assigning first the primary IPs as it can fail some validation step
        if PRIMARY_IPS_ENABLED:
            if data["vlan_type"]:
                vlan = self._get_vlan(data["vlan_type"], device)
                if vlan is None:
                    return
            else:
                vlan = data["vlan"]

            if not self._is_vlan_valid(vlan, device):
                return

            self._assign_primary(device, vlan, skip_ipv6_dns=data["skip_ipv6_dns"],
                                 cassandra_instances=int(data["cassandra_instances"]))

        self._assign_mgmt(device)

    def _format_logs(self):
        """Return all log messages properly formatted."""
        return "\n".join(
            "[{level}] {msg}".format(level=LOG_LEVEL_CODES.get(level), msg=message) for level, message in self.log
        )

    def _assign_mgmt(self, device):
        """Create a management interface in the device and assign to it a management IP."""
        iface = self._add_iface(MGMT_IFACE_NAME, device, mgmt=True)

        # determine prefix appropriate to site of device
        try:
            prefix = Prefix.objects.get(
                site=device.site, role__slug="management", tenant=device.tenant, status="active"
            )
        except ObjectDoesNotExist:
            self.log_failure(f"Can't find management prefix for device {device.name} on site {device.site.slug}.")
            return

        self.log_info(f"Selecting address from prefix {prefix.prefix}")
        ip_address = prefix.get_first_available_ip()
        if ip_address is None:
            self.log_failure(f"Unable to find an available IP in prefix {prefix.prefix}")
            return

        if device.tenant and device.tenant.slug == FRACK_TENANT_SLUG:
            dns_name = f"{device.name}.mgmt.frack.{device.site.slug}.wmnet"
        else:
            dns_name = f"{device.name}.mgmt.{device.site.slug}.wmnet"

        self._add_ip(ip_address, dns_name, prefix, iface, device)

    def _assign_primary(self, device, vlan, *, skip_ipv6_dns=False, cassandra_instances=0):
        """Create a primary interface in the device and assign to it an IPv4, a mapped IPv6 and related DNS records.

        If Cassandra instances is greater than zero allocate additional IPs for those with hostname
        $HOSTNAME-a, $HOSTNAME-b, etc.

        """
        prefixes_v4 = vlan.prefixes.filter(prefix__family=4, status="active")  # Must always be one
        prefixes_v6 = vlan.prefixes.filter(prefix__family=6, status="active")  # Can either be one or not exists
        if len(prefixes_v4) != 1 or len(prefixes_v6) > 1:
            self.log_failure(f"Unsupported case, found {len(prefixes_v4)} v4 prefixes and {len(prefixes_v6)} v6 "
                             f"prefixes, expected 1 and 0 or 1 respectively.")
            return

        prefix_v4 = prefixes_v4[0]
        prefix_v6 = None
        if prefixes_v6:
            prefix_v6 = prefixes_v6[0]

        self.log_info(f"Selecting address from prefix {prefix_v4.prefix}")

        ip_address = prefix_v4.get_first_available_ip()
        if ip_address is None:
            self.log_failure(f"Unable to find an available IP in prefix {prefix_v4.prefix}")
            return

        iface = self._add_iface(PRIMARY_IFACE_NAME, device, mgmt=False)

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
        self.log_success(f"Marked IPv4 address {ip_v4} as primary IPv4 for device {device.name}")

        if device.site.slug not in MIGRATED_PRIMARY_SITES:
            self._print_info_for_commit(device.site.slug, ip_v4, dns_name)

        # Allocate additional IPs
        for letter in ascii_lowercase[:cassandra_instances]:
            extra_ip_address = prefix_v4.get_first_available_ip()
            extra_dns_name = f"{device.name}-{letter}.{dns_suffix}"
            self._add_ip(extra_ip_address, extra_dns_name, prefix_v4, iface, device)
            if device.site.slug not in MIGRATED_PRIMARY_SITES:
                self._print_info_for_commit(device.site.slug, extra_ip_address, extra_dns_name)

        if prefix_v6 is None:
            self.log_warning(f"No IPv6 prefix found for VLAN {vlan.name}, skipping IPv6 allocation.")
            return

        dns_name_v6 = dns_name
        if skip_ipv6_dns:
            self.log_warning("Not assigning DNS name to the IPv6 address as requested.")
            dns_name_v6 = ""

        # Generate the IPv6 address embedding the IPv4 address, for example from an IPv4 address 10.0.0.1 and an
        # IPv6 prefix 2001:db8:3c4d:15::/64 the mapped IPv6 address 2001:db8:3c4d:15:10:0:0:1/64 is generated.
        prefix_v6_base, prefix_v6_mask = str(prefix_v6).split("/")
        mapped_v4 = str(ip_v4).split('/')[0].replace(".", ":")
        ipv6_address = f"{prefix_v6_base.rstrip(':')}:{mapped_v4}/{prefix_v6_mask}"
        ip_v6 = self._add_ip(ipv6_address, dns_name_v6, prefix_v6, iface, device)
        device.primary_ip6 = ip_v6
        device.save()
        self.log_success(f"Marked IPv6 address {ip_v6} as primary IPv6 for device {device.name}")

        if device.site.slug not in MIGRATED_PRIMARY_SITES and dns_name_v6:
            self._print_info_for_commit(device.site.slug, ip_v6, dns_name_v6)

    def _print_info_for_commit(self, site, address, dns_name):
        """Print a warning message that a manual commit is required with the details of the record."""
        ip = ipaddress.ip_interface(address).ip
        self.log_warning(f"DC {site} has not yet been migrated for primary records. Manual "
                         f"commit in the operations/dns repository is required. See "
                         f"[DNS Transition](https://wikitech.wikimedia.org/wiki/Server_Lifecycle/DNS_Transition)."
                         f"\n\n    IPv{ip.version}:  {ip}\n    PTRv{ip.version}: {ip.reverse_pointer}"
                         f"\n    DNSv{ip.version}: {dns_name}")

    def _get_vlan(self, vlan_type, device):
        """Find and return the appropriate VLAN that matches the type and device location."""
        if device.site.slug in ("eqiad", "codfw"):
            # TODO: add support for additional VLANs of a given type (e.g. private2)
            vlan_name = f"{vlan_type}1-{device.rack.group.slug.split('-')[-1]}-{device.site.slug}"
        else:
            if vlan_type not in VLAN_POP_TYPES:
                self.log_failure(f"VLAN type {vlan_type} not available in site {device.site.slug}, skipping")
                return

            vlan_name = f"{vlan_type}1-{device.site.slug}"

        try:
            return VLAN.objects.get(name=vlan_name, status="active")
        except ObjectDoesNotExist:
            self.log_failure(f"Unable to find VLAN with name {vlan_name}")

    def _is_vlan_valid(self, vlan, device):
        """Try to ensure that the VLAN matches the device location."""
        if vlan.site != device.site:
            self.log_failure(
                f"Skipping device {device.name}, mismatch site for VLAN {vlan.name}: "
                f"{device.site.slug} (device) != {vlan.site.slug} (VLAN)."
            )
            return False

        if vlan.tenant != device.tenant:
            self.log_failure(
                f"Skipping device {device.name}, mismatch tenant for VLAN {vlan.name}: "
                f"{device.tenant} (device) != {vlan.tenant} (VLAN)"
            )
            return False

        # Attempt to validate the row
        row = device.rack.group.slug.split("-")[-1]
        possible_rows = [part for part in vlan.name.split("-") if len(part) == 1]
        if len(possible_rows) == 1:
            if row != possible_rows[0]:
                self.log_failure(
                    f"Skipping device {device.name}, mismatch row for VLAN {vlan.name}: "
                    f"{row} (device) != {possible_rows[0]} (VLAN)"
                )
                return False
        else:
            self.log_warning(f"Unable to verify if VLAN {vlan.name} matches row {row} of device {device.name}")

        return True

    def _add_iface(self, name, device, *, mgmt=False):
        """Add an interface to the device."""
        iface = Interface(name=name, mgmt_only=mgmt, device=device, type=InterfaceTypeChoices.TYPE_1GE_FIXED)
        iface.save()
        self.log_success(f"Created interface {name} on device {device.name} (mgmt={mgmt})")
        return iface

    def _add_ip(self, address, dns_name, prefix, iface, device):
        """Assign an IP address to the interface."""
        address = IPAddress(
            address=address,
            status="active",
            dns_name=dns_name,
            vrf=prefix.vrf.pk if prefix.vrf else None,
            interface=iface,
            tenant=device.tenant,
        )
        address.save()
        self.log_success(f"Assigned IPv{prefix.family} {address} to interface {iface.name} on device {device.name} "
                         f"with DNS name '{dns_name}'.")

        return address
