"""Generates ready to consume capirca definiton files."""

from collections import defaultdict
from io import StringIO
from re import subn

from django.contrib.contenttypes.models import ContentType

from dcim.models import Interface
from ipam.models import IPAddress
from virtualization.models import VMInterface

from extras.scripts import Script


class GetHosts(Script):
    class Meta:
        name = "Capirca hosts definitions"
        description = "Returns all the Netbox hosts IPs and VIPs in a Capirca NETWORKS.net format."

    def process_ipaddress(self, ipaddress):
        # Several types of IPs:
        # 1. the interface IPs (device or VM)
        # 2. the VIPs

        # if the IP is assigned to an interface (physical device)
        if ipaddress.assigned_object_type == self.interface_ct and ipaddress.assigned_object:
            # Skip management IPs
            if ipaddress.assigned_object.mgmt_only:
                return None, None
            # Skip non servers
            if not ipaddress.assigned_object.device.device_role.slug == "server":
                return None, None
            # get the hostname
            hostname = ipaddress.assigned_object.device.name
        # if the IP is assigned to an VM interface
        elif ipaddress.assigned_object_type == self.vm_ct and ipaddress.assigned_object:
            # get the hostname
            hostname = ipaddress.assigned_object.virtual_machine.name
        elif ipaddress.role == 'vip' and ipaddress.dns_name:
            hostname = ipaddress.dns_name
        else:
            return None, None

        return hostname, ipaddress.address.ip

    def generate_output(self, singles, groups):
        output = StringIO()
        # Keep decent indentation (for nothing as Netbox strips empty characters)
        for name, networks in sorted(singles.items()):
            sorted_networks = sorted(networks)
            output.write('{} = {} # {}\n'.format(name, str(sorted_networks.pop(0)), name))
            for network in sorted_networks:
                output.write('{} # {}\n'.format(str(network).rjust(len(name) + len(str(network)) + 3), name))

        output.write('\n\n\n')  # Give me some space
        # And now create the groups
        for name, members in sorted(groups.items()):
            sorted_members = sorted(members)
            output.write('{}_group = {}\n'.format(name, sorted_members.pop(0)))
            for member in sorted_members:
                output.write('{}\n'.format(member.rjust(len(name) + len(member) + 9)))

        return output.getvalue()

    def run(self, data, commit):
        hosts = defaultdict(set)
        groups = defaultdict(set)
        self.interface_ct = ContentType.objects.get_for_model(Interface)
        self.vm_ct = ContentType.objects.get_for_model(VMInterface)

        # Iterate over all the IPs, we're going to sort/filter them later on
        for ipaddress in IPAddress.objects.filter(status="active"):

            hostname, ip = self.process_ipaddress(ipaddress)
            if not hostname or not ip:
                continue

            # We group the IPs by hosts
            # Don't do set(ip) directly as it tries to iterate over it and runs forever
            hosts[hostname].add(ip)

        for hostname in hosts.keys():
            # create the grouping key (device prefix), best effort
            group, sub_count = subn(r'\d{4}', '', hostname)
            if sub_count:
                groups[group].add(hostname)

        self.log_success("Generated successfully, see the output tab for result.")
        return self.generate_output(hosts, groups)
