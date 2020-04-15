import ipaddress

from django.core.exceptions import ObjectDoesNotExist

from dcim.choices import InterfaceTypeChoices
from dcim.models import Device, Interface
from ipam.choices import IPAddressStatusChoices
from ipam.models import Prefix, IPAddress
from extras.scripts import Script, StringVar


class CreateManagementInterface(Script):
    class Meta:
        name = "Create management interface"
        description = "Create a management interface for specified device(s) and assign an IP address(es)."

    device = StringVar(
        description="Device name(s) to add management interface(s) to (space separated)",
    )

    def _add_ip_to_interface(self, device, interface):
        """Create an IP address for a device if appropriate from the correct prefix."""
        if interface.ip_addresses.all():
            message = "refusing to create additional IP address for mgmt on {}".format(device.name)
            self.log_info(message)
            return message

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
                status=IPAddressStatusChoices.STATUS_ACTIVE,
                family=prefix.family,
            )
            # save ASAP
            newip.save()
            newip.vrf = prefix.vrf.pk if prefix.vrf else None
            # assign ip to interface
            newip.interface = interface
            newip.tenant = device.tenant
            newip.save()

            message = "Created IP {} for mgmt on device {}".format(newip, device.name)
            self.log_success(message)
            return message

        # fall through to failure
        message = "Not enough IPs to allocate one on prefix {}".format(prefix.prefix)
        self.log_failure(message)
        return message

    def run(self, data):
        """Create a 'mgmt' interface, and, if requested, allocate an appropriate IP address."""
        # we don't filter status or role here so we can report later on rather that just not finding them
        devices = Device.objects.filter(name__in=data['device'].split())
        messages = []
        if not devices:
            message = "No devices found for specified list."
            self.log_failure(message)
            return message

        for device in devices:
            self.log_info("processing device {}".format(device.name))
            if (device.status not in ("inventory", "planned")):
                self.log_failure("device {} is not in state Inventory or Planned, skipping".format(device))
                continue
            if (device.device_role.slug != "server"):
                self.log_failure("device {} is not a server, skipping".format(device))
                continue
            try:
                mgmt = device.interfaces.get(name='mgmt')
                self.log_info("mgmt already exists for device {}".format(device.name))
            except ObjectDoesNotExist:
                # create interface of name mgmt, is_mgmt flag set of type 1G Ethernet
                mgmt = Interface(name="mgmt", mgmt_only=True, device=device, type=InterfaceTypeChoices.TYPE_1GE_FIXED)
                mgmt.save()

            messages.append(self._add_ip_to_interface(device, mgmt))

        return "\n".join(messages)
