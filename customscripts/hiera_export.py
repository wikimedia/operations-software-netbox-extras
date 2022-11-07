"""A script to generate data used by hiera"""
import json

from typing import Dict, List

from dcim.choices import DeviceStatusChoices
from dcim.models import Device, Interface
from virtualization.choices import VirtualMachineStatusChoices
from virtualization.models import VirtualMachine

from extras.scripts import Script

HW_EXCLUDE_STATUSES = (
    DeviceStatusChoices.STATUS_DECOMMISSIONING,
    DeviceStatusChoices.STATUS_INVENTORY,
    DeviceStatusChoices.STATUS_OFFLINE,
    DeviceStatusChoices.STATUS_PLANNED,
)
VM_EXCLUDE_STATUSES = (
    VirtualMachineStatusChoices.STATUS_DECOMMISSIONING,
    VirtualMachineStatusChoices.STATUS_OFFLINE,
    VirtualMachineStatusChoices.STATUS_PLANNED,
)
MGMT_EXCLUDE_STATUSES = (
    DeviceStatusChoices.STATUS_OFFLINE,
    DeviceStatusChoices.STATUS_PLANNED,
    DeviceStatusChoices.STATUS_DECOMMISSIONING,
)


# pylint: disable=too-few-public-methods
class HieraExport(Script):
    """Class to export Netbox data for hiera consumption"""

    class Meta:
        """Required by netbox"""

        name = "Hiera host definition export"
        description = "Return All hosts and their associated hiera information"
        commit_default = False

    @staticmethod
    def _generate_hosts(devices: List[Device]) -> Dict:
        """Generate the necessary output dictionary

        Arguments:
            devices (List[Device]): a list of netbox devices

        Returns:
            dict: a dictionary of values for hiera

        """
        hosts = {}

        for device in devices:
            hosts[device.name] = {
                # profile::netbox::host will load this data into netbox::host
                # We can then make the data available via netbox::$functions
                'location': {
                    'site': device.site.slug,
                },
                'status': device.status,
            }
            if isinstance(device, Device):
                if device.rack:
                    hosts[device.name]['location']['rack'] = device.rack.name
                    if device.rack.location:
                        hosts[device.name]['location']['row'] = device.rack.location.slug
            if isinstance(device, VirtualMachine):
                if device.cluster:
                    hosts[device.name]['location']['ganeti_group'] = device.cluster.name
                    hosts[device.name]['location']['ganeti_cluster'] = device.cluster.group.name
        return hosts

    @staticmethod
    def _generate_mgmt(interfaces: List[Interface]) -> Dict:
        """Generate the list of management interfaces

        Arguments:
            devices (List[Interface]): a list of netbox interfaces

        Returns:
            dict: a dictionary of values for hiera

        """
        res = {}

        for interface in interfaces:
            device = interface.device
            if device.status in MGMT_EXCLUDE_STATUSES:
                continue
            if interface.count_ipaddresses < 1:
                continue

            # Tenant is not production, skip because puppet doesn't
            # have much power there.
            if device.tenant is not None:
                continue

            data = {
                'row': device.rack.location.slug,
                'rack': device.rack.name,
                'site': device.site.slug,
            }

            address = interface.ip_addresses.first()
            res[address.dns_name] = data

        return res

    def run(self, data: Dict, commit: bool) -> str:
        """Required by netbox"""
        # pylint: disable=unused-argument
        results = {'hosts': {}, 'common': {'mgmt': {}}}
        hw_devices = Device.objects.filter(
            device_role__slug="server", tenant__isnull=True
        ).exclude(status__in=HW_EXCLUDE_STATUSES)
        vm_devices = VirtualMachine.objects.filter(tenant__isnull=True).exclude(
            status__in=VM_EXCLUDE_STATUSES)
        mgmt_interfaces = Interface.objects.filter(mgmt_only=True)
        results['hosts'].update(self._generate_hosts(hw_devices))
        results['hosts'].update(self._generate_hosts(vm_devices))
        results['common']['mgmt'].update(self._generate_mgmt(mgmt_interfaces))
        return json.dumps(results)
