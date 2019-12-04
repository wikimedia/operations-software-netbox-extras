import ipaddress

from django.core.exceptions import ObjectDoesNotExist

from dcim.constants import IFACE_TYPE_1GE_FIXED
from dcim.models import Device, Interface
from ipam.constants import IPADDRESS_STATUS_ACTIVE
from ipam.models import Prefix, IPAddress
from extras.scripts import Script, ObjectVar, BooleanVar


class CreateManagementInterface(Script):
    class Meta:
        name = "Create Management Interface"
        description = "Create a management interface for a specified device and assign an IP address."

    device = ObjectVar(
        description="The Device to add management interface to",
        queryset=Device.objects.filter(device_role__slug="server"),
    )
    add_ip = BooleanVar(
        description="Automatically add IP address from appropriate management network at site.", default=True
    )

    def _add_ip_to_interface(self, device, interface):
        # determine prefix appropriate to site of device
        try:
            prefix = Prefix.objects.get(site=device.site, role__slug="management", tenant=device.tenant)
        except ObjectDoesNotExist:
            message = "Can't find prefix for site {} on device {}".format(device.site.slug, device.name)
            self.log_failure(message)
            return message
        self.log_info("Selecting address from network {}".format(prefix.prefix))
        available_ips = iter(prefix.get_available_ips())

        # disable 0net skipping on frack
        if device.tenant and device.tenant.slug == 'fr-tech':
            zeroth_net = None
        else:
            # skip the first /24 net as this is reserved for network devices
            zeroth_net = list(ipaddress.ip_network(prefix.prefix).subnets(new_prefix=24))[0]

        ip = None
        for ip in available_ips:
            address = ipaddress.ip_address(ip)
            if zeroth_net is None or address not in zeroth_net:
                break
            else:
                ip = None

        if ip:
            # create IP address as child of appropriate prefix
            newip = IPAddress(
                address="{}/{}".format(ip, prefix.prefix.prefixlen),
                status=IPADDRESS_STATUS_ACTIVE,
                family=prefix.family,
            )
            # save ASAP
            newip.save()
            newip.vrf = prefix.vrf.pk if prefix.vrf else None
            # assign ip to interface
            newip.interface = interface
            newip.tenant = device.tenant
            newip.save()

            message = "Created ip {} for mgmt on device {}".format(newip, device.name)
            self.log_success(message)
            return message

        # fall through to failure
        message = "Not enough IPs to allocate one on prefix {}".format(prefix.prefix)
        self.log_failure(message)
        return message

    def run(self, data):
        """Create a 'mgmt' interface, and, if requested, allocate an appropriate IP address."""
        device = data['device']

        try:
            mgmt = device.interfaces.get(name='mgmt')
            self.log_info("mgmt already exists for device {}".format(device.name))
        except ObjectDoesNotExist:
            # create interface of name mgmt, is_mgmt flag set of type 1G Ethernet
            mgmt = Interface(name="mgmt", mgmt_only=True, device=device, type=IFACE_TYPE_1GE_FIXED)
            mgmt.save()

        if data['add_ip']:
            return self._add_ip_to_interface(device, mgmt)

        else:
            message = "Created mgmt on device {}".format(device.name)
            self.log_success(message)
            return message
