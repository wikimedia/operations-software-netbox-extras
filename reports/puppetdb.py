"""Report parity errors between PuppetDB and Netbox."""
import configparser

from copy import deepcopy
from functools import lru_cache

import requests

from dcim.choices import DeviceStatusChoices
from dcim.models import Device
from extras.reports import Report
from virtualization.models import VirtualMachine

CONFIG_FILE = "/etc/netbox/reports.cfg"

# slugs for roles which we care about
INCLUDE_ROLES = ("server",)

# statuses that only warn for parity failures
EXCLUDE_STATUSES = (
    DeviceStatusChoices.STATUS_DECOMMISSIONING,
    DeviceStatusChoices.STATUS_INVENTORY,
    DeviceStatusChoices.STATUS_OFFLINE,
    DeviceStatusChoices.STATUS_PLANNED,
    DeviceStatusChoices.STATUS_STAGED,
)
EXCLUDE_AND_FAILED_STATUSES = EXCLUDE_STATUSES + (DeviceStatusChoices.STATUS_FAILED,)
DEVICE_QUERY = Device.objects.filter(role__slug__in=INCLUDE_ROLES, tenant__isnull=True)


class PuppetDBDataMixin:
    """Provides callables which cache their returns, which access PuppetDB data."""

    description = __doc__

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
        response = requests.get(url, verify=config["puppetdb"]["ca_cert"], timeout=60)
        if response.status_code != 200:
            raise RuntimeError(f"Cannot connect to PuppetDB {url} - {response.status_code} {response.text}")
        return response.json()


class VirtualMachines(Report, PuppetDBDataMixin):
    """Report parity errors between PuppetDB and Netbox for Virtual Machines."""

    description = __doc__

    def test_puppetdb_vms_in_netbox(self):
        """Check that all PuppetDB VMs are in Netbox VMs."""
        vms = list(VirtualMachine.objects.values_list("name", flat=True))
        success = 0
        puppetdb_isvirtual = self._get_puppetdb_fact("is_virtual")
        for device, is_virtual in puppetdb_isvirtual.items():
            if not is_virtual:
                continue

            if device not in vms:
                self.log_failure(None, f"missing VM from Netbox: {device}")
            else:
                success += 1

        self.log_success(None, f"{success} VMs that are in PuppetDB are also in Netbox VMs")

    def test_netbox_vms_in_puppetdb(self):
        """Check that all Netbox VMs are in PuppetDB VMs."""
        vms = VirtualMachine.objects.filter(tenant__isnull=True).exclude(status=DeviceStatusChoices.STATUS_OFFLINE)
        puppetdb_isvirtual = self._get_puppetdb_fact("is_virtual")
        success = 0
        for vm in vms:
            if vm.name not in puppetdb_isvirtual:
                self.log_failure(vm, "missing VM from PuppetDB")
            elif not puppetdb_isvirtual[vm.name]:
                self.log_failure(vm, "expected VM marked as Physical in PuppetDB")
            else:
                success += 1

        self.log_success(None, f"{success} VMs that are in Netbox are also in PuppetDB VMs")


class PhysicalHosts(Report, PuppetDBDataMixin):
    """Report parity errors between PuppetDB and Netbox for physical devices."""

    description = __doc__

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
                    (f"Device is in PuppetDB but is {invalid_device.get_status_display()}"
                     " in Netbox (should be Active or Failed)")
                )
            else:
                self.log_failure(None, f"expected device missing from Netbox: {device}")

        self.log_success(None, f"{success} physical devices that are in PuppetDB are also in Netbox")

    def test_netbox_in_puppetdb(self):
        """Check that all Netbox physical devices are in PuppetDB."""
        devices = DEVICE_QUERY.exclude(status__in=EXCLUDE_AND_FAILED_STATUSES)
        success = 0
        puppetdb_devices = self._get_puppetdb_fact("is_virtual")

        for device in devices:
            if device.name not in puppetdb_devices:
                self.log_failure(
                    device,
                    (f"Device is {device.get_status_display()} in Netbox"
                     f" but is missing from PuppetDB (should be {EXCLUDE_AND_FAILED_STATUSES})")
                )
            elif puppetdb_devices[device.name]:  # True if device is is_virtual
                self.log_failure(device, "expected physical device marked as virtual in PuppetDB")
            else:
                success += 1

        self.log_success(None, f"{success} physical devices that are in Netbox are also in PuppetDB")

    def test_puppetdb_serials(self):
        """Check that devices that exist in both PuppetDB and Netbox have matching serial numbers."""
        devices = deepcopy(DEVICE_QUERY)
        puppetdb_serials = self._get_puppetdb_fact("serialnumber")
        success = 0

        for device in devices:
            if device.name not in puppetdb_serials:
                continue
            if device.serial != puppetdb_serials[device.name]:
                self.log_failure(
                    device,
                    f"mismatched serials: {device.serial} (netbox) != {puppetdb_serials[device.name]} (puppetdb)"
                )
            else:
                success += 1

        self.log_success(None, f"{success} physical devices have matching serial numbers")

    def test_puppetdb_models(self):
        """Check that the device productname in PuppetDB match models set in Netbox."""
        devices = deepcopy(DEVICE_QUERY)
        puppetdb_models = self._get_puppetdb_fact("productname")
        success = 0

        for device in devices:
            if device.name not in puppetdb_models:
                continue

            # Split on ' - ' to remove the WMF standard configurations from the names (i.e. - ConfigA 202107)
            if device.device_type.model.split(" - ")[0] != puppetdb_models[device.name]:
                self.log_failure(
                    device,
                    (f"mismatched device models: {device.device_type.model}"
                     f" (netbox) != {puppetdb_models[device.name]} (puppetdb)")
                )
            else:
                success += 1

        self.log_success(None, f"{success} devices have matching model names")
