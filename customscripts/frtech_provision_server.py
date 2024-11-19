from django.core.exceptions import ValidationError
from utilities.exceptions import AbortScript

from dcim.choices import InterfaceTypeChoices
from dcim.models import Device, Interface
from extras.scripts import ChoiceVar, IntegerVar, ObjectVar, Script, StringVar
from ipam.models import IPAddress, Prefix, VLAN

from wmf_scripts_imports.common import format_logs, port_to_iface, Importer

MGMT_IFACE_NAME = "mgmt"
HOST_IFACE_PRIMARY = "bond0"
FRACK_TENANT_SLUG = "fr-tech"
VLAN_TYPES = (
    "fundraising",
    "administration",
    "payments",
    "listenerdmz",
    "bastion"
)


class ProvisionFundraisingServerNetwork(Script, Importer):

    class Meta:
        name = "Fundraising Server Provision for Dual-Switch Uplinks"
        description = "More exactly: IPs, interfaces (including mgmt and switch), vlan."
        commit_default = False

    device = ObjectVar(
        description=("Inventory or planned server."),
        model=Device,
        query_params={
            'role': 'server',
            'status': ('inventory', 'planned'),
            'tenant': FRACK_TENANT_SLUG,
            'has_primary_ip': False
        }
    )

    z_port = IntegerVar(label="Switch port",
                        description=("Physical port number (0-47) (same port will be configured "
                                     "for the host on both frack switches at the site."),
                        min_value=0,
                        max_value=47)

    interface_type_choices = (
        (InterfaceTypeChoices.TYPE_1GE_FIXED, '1G'),
        (InterfaceTypeChoices.TYPE_10GE_SFP_PLUS, '10G'),
        (InterfaceTypeChoices.TYPE_25GE_SFP28, '25G')
    )
    interface_type = ChoiceVar(label="Interface type/speed",
                               description="Interface speed",
                               choices=interface_type_choices)

    vlan_type = ChoiceVar(
        choices=[(value, value) for value in VLAN_TYPES],
        label="VLAN Type",
        description=("The VLAN type to use for assigning the primary IPs. The specific VLAN will be automatically "
                     "chosen based on device location.")
    )

    cable_id_a = StringVar(label="Cable ID A", description="Cable ID/label on link to switch A", required=False)
    cable_id_b = StringVar(label="Cable ID B", description="Cable ID/label on link to switch B", required=False)

    def run(self, data: dict, _commit: bool) -> str:
        """Run the script and return all the log messages."""
        self.log_info(f"Called with parameters: {data}")
        self.provision_server(data)
        return format_logs(self.messages)

    def provision_server(self, data: dict) -> None:  # noqa: too-many-return-statements
        """Process a single device."""
        device = data['device']
        assign_mgmt = True

        if not device.rack:
            raise AbortScript(f"{device}: missing rack information, aborting.")

        ifaces = device.interfaces.all()
        if ifaces:
            # If only the mgmt one is set up and it looks right we continue and leave it alone
            if (len(ifaces) == 1 and ifaces[0].name == MGMT_IFACE_NAME and ifaces[0].count_ipaddresses == 1
                    and ifaces[0].ip_addresses.all()[0].dns_name):
                self.log_warning(f"{device}: Skipping assignment of MGMT interface because already allocated")
                assign_mgmt = False
            else:
                # If multiple exist, or the one that does exist isn't mgmt we bail
                raise AbortScript(f"{device}: interfaces already defined: {[i.name for i in ifaces]}, skipping.")

        cable_ids = {'a': data['cable_id_a'], 'b': data['cable_id_b']}
        # Get related objects
        vlan = VLAN.objects.get(tenant__slug=FRACK_TENANT_SLUG, site=device.site,
                                name__startswith=f"frack-{data['vlan_type']}")
        try:
            prefix = vlan.prefixes.get()
        except Prefix.MultipleObjectsReturned as e:
            raise AbortScript(f"{device}: Vlan {vlan} has more than one IP prefix attached.") from e

        # Create server bond0 interface and assign IP
        bond_iface = self._add_iface(HOST_IFACE_PRIMARY, device, iface_type=InterfaceTypeChoices.TYPE_LAG)
        dns_name = f"{device.name}.frack.{device.site.slug}.wmnet"
        primary_ip = self._add_ip(dns_name, prefix, bond_iface, device)
        device.primary_ip4 = primary_ip
        device.save()
        self.log_success(f"{device}: set primary IP to {primary_ip}")

        # Create mgmt interface on server if needed
        if assign_mgmt:
            iface_type = InterfaceTypeChoices.TYPE_1GE_FIXED
            mgmt_iface = self._add_iface(MGMT_IFACE_NAME, device, iface_type=iface_type, mgmt=True)
            mgmt_vlan = VLAN.objects.get(tenant__slug=FRACK_TENANT_SLUG, site=device.site, role__slug='management')
            mgmt_pfx = mgmt_vlan.prefixes.get(status='active')
            dns_name = f"{device.name}.mgmt.frack.{device.site.slug}.wmnet"
            device.oob_ip = self._add_ip(dns_name, mgmt_pfx, mgmt_iface, device)
            device.save()
            self.log_success(f"{device}: set {device.oob_ip} as out-of-band IP for host.")

        switches = Device.objects.filter(tenant__slug=FRACK_TENANT_SLUG, role__slug='asw',
                                         status='active', site=device.site, rack=device.rack)
        # Configure ports and connections
        for switch in switches:
            # switch_member is either 'a' or 'b' based on our naming convention
            switch_member = switch.name.split('-')[1][-1]
            # Add/configure switch int
            sw_int_name = port_to_iface(data['z_port'], switch, data['interface_type'])
            sw_int = self._add_iface(name=sw_int_name, device=switch, iface_type=data['interface_type'])
            sw_int.mtu = 9192
            sw_int.mode = 'access'
            sw_int.untagged_vlan = vlan
            sw_int.save()
            self.log_success(f"{device}: Set access vlan on {switch.name} {sw_int} to {vlan} and MTU to 9192.")
            # Add server int with dummy name
            server_int_name = f"PRIMARY_{switch_member}".upper()
            server_int = self._add_iface(name=server_int_name, device=device, iface_type=data['interface_type'],
                                         description="dummy interface name")
            server_int.lag = bond_iface
            server_int.save()
            # Connect it to the switch
            self._create_cable(sw_int, server_int, label=cable_ids[switch_member])

    def _add_iface(self, name: str, device: Device, iface_type: str,
                   mgmt: bool = False, description: str = '') -> Interface:
        """Add an interface to the device, if it already exists re-create if unused."""
        self._remove_existing_int(name, device)
        # Make new interface with required params
        iface = Interface(name=name, mgmt_only=mgmt, device=device, type=iface_type, description=description)
        # Validate new interface against our custom validator, esp. important for T3 port blocks
        try:
            iface.full_clean()
        except ValidationError as e:
            raise AbortScript(f"{device}: new interface {name} fails validation checks - {e.messages[0]}.") from e

        iface.save()
        self.log_success(f"{device}: created interface {name} (mgmt={mgmt})")
        return iface

    def _remove_existing_int(self, name: str, device: Device) -> None:
        """Removes existing interface from device if it is unused"""
        if device.role.slug == 'asw':
            # Get any interface on switch that is built on this port, i.e. ge/xe/et
            port_id = name.split('/')[-1]
            existing_iface = Interface.objects.filter(device=device, name__endswith=port_id)
        else:
            existing_iface = Interface.objects.filter(device=device, name=name)

        for iface in existing_iface:
            if iface.cable or iface.enabled:
                raise AbortScript(f"{device}: interface {iface} already exists and is enabled or has cable attached.")

            self.log_info(f"{device}: deleting unused existing interface {iface}")
            iface.delete()

    def _add_ip(self, dns_name: str, prefix: Prefix, iface: Interface, device: Device) -> Interface:
        """Allocate IP from provided prefix and assign it to interface."""
        ip_address = prefix.get_first_available_ip()
        if ip_address is None:
            raise AbortScript(f"{device}: unable to find an available IP in prefix {prefix.prefix}")

        iface_address = IPAddress(
            address=ip_address,
            status="active",
            dns_name=dns_name,
            assigned_object=iface,
            tenant=device.tenant,
        )
        iface_address.save()
        self.log_success(f"{device}: assigned {iface_address} to interface {iface.name} with DNS name '{dns_name}'.")

        return iface_address
