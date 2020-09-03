import ipaddress

from string import ascii_lowercase

from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q

from dcim.choices import InterfaceTypeChoices
from dcim.models import Device, Interface
from extras.constants import LOG_LEVEL_CODES
from extras.scripts import BooleanVar, ChoiceVar, ObjectVar, Script, StringVar
from ipam.models import IPAddress, Prefix, VLAN
from utilities.forms import APISelect


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
