"""Generates ready to consume capirca definiton files."""

from collections import defaultdict
from io import StringIO
from re import subn

from django.contrib.contenttypes.models import ContentType

from dcim.models import Interface
from ipam.models import IPAddress
from virtualization.models import VMInterface

from core.models import Job
from extras.scripts import Script, ScriptModel
from utilities.exceptions import AbortScript

# Present in Netbox requirements.txt
from dulwich.patch import unified_diff


class GetHosts(Script):
    class Meta:
        name = "Capirca hosts definitions"
        description = "Returns all the Netbox hosts IPs, Anycast IPs and VIPs in a Capirca NETWORKS.net format."
        job_timeout = 900  # noqa: unused-variable
        scheduling_enabled = False  # noqa: unused-variable
        commit_default = False  # noqa: unused-variable

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.interface_ct = ContentType.objects.get_for_model(Interface)
        self.vm_ct = ContentType.objects.get_for_model(VMInterface)

    def process_ipaddress(self, ipaddress: IPAddress) -> tuple:
        # Several types of IPs:
        # 1. the interface IPs (device or VM)
        # 2. the VIPs

        # if the IP is assigned to an interface (physical device)
        if ipaddress.assigned_object_type == self.interface_ct and ipaddress.assigned_object:
            # Skip management IPs
            if ipaddress.assigned_object.mgmt_only:
                return None, None
            # Skip non servers
            if not ipaddress.assigned_object.device.role.slug == "server":
                return None, None
            # get the hostname
            hostname = ipaddress.assigned_object.device.name
        # if the IP is assigned to an VM interface
        elif ipaddress.assigned_object_type == self.vm_ct and ipaddress.assigned_object:
            # get the hostname
            hostname = ipaddress.assigned_object.virtual_machine.name
        elif ipaddress.role in ("vip", "anycast") and ipaddress.dns_name:
            hostname = ipaddress.dns_name
        else:
            return None, None

        return hostname, ipaddress.address.ip

    def generate_output(self, singles: dict, groups: dict) -> str:
        output = StringIO()
        # Keep decent indentation (for nothing as Netbox strips empty characters)
        for name, networks in sorted(singles.items()):
            sorted_networks = sorted(networks)
            output.write(f"{name} = {str(sorted_networks.pop(0))} # {name}\n")
            for network in sorted_networks:
                output.write(f"{str(network).rjust(len(name) + len(str(network)) + 3)} # {name}\n")

        output.write("\n\n\n")  # Give me some space
        # And now create the groups
        for name, members in sorted(groups.items()):
            sorted_members = sorted(members)
            output.write(f"{name}_group = {sorted_members.pop(0)}\n")
            for member in sorted_members:
                output.write(f"{member.rjust(len(name) + len(member) + 9)}\n")

        return output.getvalue()

    def run(self, data: dict, commit: bool) -> str:  # noqa: unused-argument
        hosts = defaultdict(set)
        groups = defaultdict(set)

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
            group, sub_count = subn(r"\d{4}", "", hostname)
            if sub_count:
                groups[group].add(hostname)

        output = self.generate_output(hosts, groups)
        if commit:
            return output

        # Find most recent run, workaround to find our own script ID
        script = ScriptModel.objects.get(name=self.class_name)
        script_id = script.result.object_id  # script.result is the current run with the "Running" status
        # if the last run is not successful, we try to find the latest successful
        last_run = Job.objects.filter(object_id=script_id, status="completed").order_by('-created').first()
        # There is no previous successful run on record, save it now
        if not last_run:
            return output

        previous_output = last_run.data['output'].encode('utf-8')
        differences = unified_diff(previous_output.splitlines(keepends=True),
                                   output.encode('utf-8').splitlines(keepends=True),
                                   fromfile=b'original', tofile=b'modified', n=1)
        diff_output = b''.join(differences).decode('utf-8')
        self.log_info(diff_output.replace('\n', '<br>'))
        if diff_output:
            raise AbortScript("See outstanding diff above, commit if correct.")

        return output
