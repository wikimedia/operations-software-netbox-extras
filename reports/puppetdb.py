"""
Report parity errors between PuppetDB and Netbox.
"""

import configparser
import requests

from functools import lru_cache

from dcim.choices import DeviceStatusChoices
from dcim.models import Device
from extras.reports import Report
from virtualization.models import VirtualMachine

VM_BLOCKLIST = ('d-i-test',)

CONFIG_FILE = "/etc/netbox/reports.cfg"

# slugs for roles which we care about
INCLUDE_ROLES = ("server",)

# statuses that only warn for parity failures
EXCLUDE_STATUSES = (
    DeviceStatusChoices.STATUS_INVENTORY,
    DeviceStatusChoices.STATUS_OFFLINE,
    DeviceStatusChoices.STATUS_PLANNED,
    DeviceStatusChoices.STATUS_DECOMMISSIONING,
)
EXCLUDE_AND_FAILED_STATUSES = EXCLUDE_STATUSES + (DeviceStatusChoices.STATUS_FAILED,)
DEVICE_QUERY = Device.objects.filter(device_role__slug__in=INCLUDE_ROLES, tenant__isnull=True)


class PuppetDBDataMixin:
    """Provides callables which cache their returns, which access PuppetDB data."""

    @lru_cache(1)
    def _get_config(self):
        """Get configuration file."""
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        return config

    @lru_cache(10)
    def _get_puppetdb_fact(self, factname):
        """Return a dictionary keyed by hostname of a specified PuppetDB fact."""
        config = self._get_config()
        url = "/".join([config["puppetdb"]["url"], "/v1/facts", factname])
        response = requests.get(url, verify=config["puppetdb"]["ca_cert"])
        if response.status_code != 200:
            raise Exception("Cannot connect to PuppetDB {} - {} {}".format(url, response.status_code, response.text))
        return response.json()


class VirtualMachines(Report, PuppetDBDataMixin):
    description = """Report parity errors between PuppetDB and Netbox for Virtual Machines"""

    def test_puppetdb_vms_in_netbox(self):
        """Check that all PuppetDB VMs are in Netbox VMs."""
        vms = list(VirtualMachine.objects.values_list("name", flat=True))
        success = 0
        puppetdb_isvirtual = self._get_puppetdb_fact("is_virtual")
        for device, is_virtual in puppetdb_isvirtual.items():
            if not is_virtual:
                continue

            if device not in vms:
                self.log_failure(None, "missing VM from Netbox: {} ".format(device))
            else:
                success += 1

        self.log_success(None, "{} VMs that are in PuppetDB are also in Netbox VMs".format(success))

    def test_netbox_vms_in_puppetdb(self):
        """Check that all Netbox VMs are in PuppetDB VMs."""

        vms = VirtualMachine.objects.exclude(status=DeviceStatusChoices.STATUS_OFFLINE)
        puppetdb_isvirtual = self._get_puppetdb_fact("is_virtual")
        success = 0
        for vm in vms:
            if vm.name not in puppetdb_isvirtual:
                if vm.name in VM_BLOCKLIST:
                    self.log_warning(vm, "missing VM from PuppetDB (ignored)")
                else:
                    self.log_failure(vm, "missing VM from PuppetDB")
            elif not puppetdb_isvirtual[vm.name]:
                self.log_failure(vm, "expected VM marked as Physical in PuppetDB")
            else:
                success += 1

        self.log_success(None, "{} VMs that are in Netbox are also in PuppetDB VMs".format(success))


class PhysicalHosts(Report, PuppetDBDataMixin):
    description = """Report parity errors between PuppetDB and Netbox for physical devices."""

    def test_puppetdb_in_netbox(self):
        """Check that all PuppetDB physical devices are in Netbox."""

        valid_netbox_devices = DEVICE_QUERY.exclude(status__in=EXCLUDE_STATUSES).values_list("name", flat=True)
        invalid_netbox_devices = DEVICE_QUERY.filter(status__in=EXCLUDE_STATUSES).values_list("name", flat=True)

        success = 0
        puppetdb_devices = self._get_puppetdb_fact("is_virtual")
        for device, is_virtual in puppetdb_devices.items():
            if is_virtual:
                continue

            if device in valid_netbox_devices:
                success += 1
            elif device in invalid_netbox_devices:
                invalid_device = Device.objects.get(name=device)
                self.log_failure(
                    invalid_device,
                    ("Device is in PuppetDB but is {} in Netbox (should be Staged, Active or Failed)")
                    .format(invalid_device.get_status_display()),
                )
            else:
                self.log_failure(None, "expected device missing from Netbox: {}".format(device))

        self.log_success(None, "{} physical devices that are in PuppetDB are also in Netbox".format(success))

    def test_netbox_in_puppetdb(self):
        """Check that all Netbox physical devices are in PuppetDB."""
        devices = DEVICE_QUERY.exclude(status__in=EXCLUDE_AND_FAILED_STATUSES)
        success = 0
        puppetdb_devices = self._get_puppetdb_fact("is_virtual")

        for device in devices:
            if device.name not in puppetdb_devices:
                self.log_failure(
                    device,
                    ("Device is {} in Netbox but is missing from PuppetDB (should be {})")
                    .format(device.get_status_display(), EXCLUDE_AND_FAILED_STATUSES),
                )
            elif puppetdb_devices[device.name]:  # True if device is is_virtual
                self.log_failure(device, "expected physical device marked as virtual in PuppetDB")
            else:
                success += 1

        self.log_success(None, "{} physical devices that are in Netbox are also in PuppetDB".format(success))

    def test_puppetdb_serials(self):
        """Check that devices that exist in both PuppetDB and Netbox have matching serial numbers."""
        devices = DEVICE_QUERY.clone()
        puppetdb_serials = self._get_puppetdb_fact("serialnumber")
        success = 0

        for device in devices:
            if device.name not in puppetdb_serials:
                continue
            if device.serial != puppetdb_serials[device.name]:
                self.log_failure(
                    device,
                    "mismatched serials: {} (netbox) != {} (puppetdb)".format(
                        device.serial, puppetdb_serials[device.name]
                    ),
                )
            else:
                success += 1

        self.log_success(None, "{} physical devices have matching serial numbers".format(success))

    def test_puppetdb_models(self):
        """Check that the device productname in PuppetDB match models set in Netbox"""
        devices = DEVICE_QUERY.clone()
        puppetdb_models = self._get_puppetdb_fact("productname")
        success = 0

        for device in devices:
            if device.name not in puppetdb_models:
                continue

            # Split on ' - ' to remove the WMF standard configurations from the names (i.e. - ConfigA 202107)
            if device.device_type.model.split(' - ')[0] != puppetdb_models[device.name]:
                self.log_failure(
                    device,
                    "mismatched device models: {} (netbox) != {} (puppetdb)".format(
                        device.device_type.model, puppetdb_models[device.name]
                    ),
                )
            else:
                success += 1

        self.log_success(None, "{} devices have matching model names".format(success))
