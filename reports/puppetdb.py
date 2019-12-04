"""
Report parity errors between PuppetDB and Netbox.
"""

import configparser
import requests

from dcim.constants import (
    DEVICE_STATUS_DECOMMISSIONING,
    DEVICE_STATUS_FAILED,
    DEVICE_STATUS_INVENTORY,
    DEVICE_STATUS_OFFLINE,
    DEVICE_STATUS_PLANNED,
)
from dcim.models import Device
from extras.reports import Report
from virtualization.models import VirtualMachine

CONFIG_FILE = "/etc/netbox/reports.cfg"

# slugs for roles which we care about
INCLUDE_ROLES = ("server",)

# statuses that only warn for parity failures
EXCLUDE_STATUSES = (
    DEVICE_STATUS_INVENTORY,
    DEVICE_STATUS_OFFLINE,
    DEVICE_STATUS_PLANNED,
    DEVICE_STATUS_DECOMMISSIONING,
)
EXCLUDE_AND_FAILED_STATUSES = EXCLUDE_STATUSES + (DEVICE_STATUS_FAILED,)


class PuppetDB(Report):
    description = __doc__

    def __init__(self, *args, **kwargs):
        """Load the data from the endpoint as needed by the reports."""
        self.config = configparser.ConfigParser()
        self.config.read(CONFIG_FILE)

        self.puppetdb_serials = self._get_puppetdb_fact("serialnumber")
        self.puppetdb_devices = self._get_puppetdb_fact("is_virtual")
        self.puppetdb_models = self._get_puppetdb_fact("productname")
        self.device_query = Device.objects.filter(device_role__slug__in=INCLUDE_ROLES, tenant__isnull=True)

        super().__init__(*args, **kwargs)

    def _get_puppetdb_fact(self, fact):
        """Query the PuppetDB proxy for a specified fact.

        Arguments:
           fact (str): The fact name to query

        Returns:
            dict: Keyed by short devicename, with te value.

        Raises:
            Exception: on communication failure.

        """
        url = "/".join([self.config["puppetdb"]["url"], "/v1/facts", fact])
        response = requests.get(url, verify=self.config["puppetdb"]["ca_cert"])
        if response.status_code != 200:
            raise Exception("Cannot connect to PuppetDB {} - {} {}".format(url, response.status_code, response.text))

        return response.json()

    def test_puppetdb_in_netbox(self):
        """Check that all PuppetDB physical devices are in Netbox."""
        valid_netbox_devices = self.device_query.exclude(status__in=EXCLUDE_STATUSES).values_list("name", flat=True)
        invalid_netbox_devices = self.device_query.filter(status__in=EXCLUDE_STATUSES).values_list("name", flat=True)

        success = 0
        for device, is_virtual in self.puppetdb_devices.items():
            if is_virtual:
                continue

            if device in valid_netbox_devices:
                success += 1
            elif device in invalid_netbox_devices:
                invalid_device = Device.objects.get(name=device)
                self.log_failure(
                    invalid_device,
                    "unexpected state for physical device: {} in netbox".format(invalid_device.get_status_display()),
                )
            else:
                self.log_failure(None, "expected device missing from Netbox: {}".format(device))

        self.log_success(None, "{} physical devices that are in PuppetDB are also in Netbox".format(success))

    def test_netbox_in_puppetdb(self):
        """Check that all Netbox physical devices are in PuppetDB."""
        devices = self.device_query.exclude(status__in=EXCLUDE_AND_FAILED_STATUSES)
        success = 0

        for device in devices:
            if device.name not in self.puppetdb_devices:
                self.log_failure(
                    device,
                    "missing physical device in PuppetDB: state {} in Netbox".format(device.get_status_display()),
                )
            elif self.puppetdb_devices[device.name]:
                self.log_failure(device, "expected physical device marked as virtual in PuppetDB")
            else:
                success += 1

        self.log_success(None, "{} physical devices that are in Netbox are also in PuppetDB".format(success))

    def test_puppetdb_serials(self):
        """Check that devices that exist in both PuppetDB and Netbox have matching serial numbers."""
        devices = self.device_query
        success = 0

        for device in devices:
            if device.name not in self.puppetdb_serials:
                continue
            if device.serial != self.puppetdb_serials[device.name]:
                self.log_failure(
                    device,
                    "mismatched serials: {} (netbox) != {} (puppetdb)".format(
                        device.serial, self.puppetdb_serials[device.name]
                    ),
                )
            else:
                success += 1

        self.log_success(None, "{} physical devices have matching serial numbers".format(success))

    def test_puppetdb_models(self):
        """Check that the device productname in PuppetDB match models set in Netbox"""
        devices = self.device_query
        success = 0

        for device in devices:
            if device.name not in self.puppetdb_models:
                continue

            if device.device_type.model != self.puppetdb_models[device.name]:
                self.log_failure(
                    device,
                    "mismatched device models: {} (netbox) != {} (puppetdb)".format(
                        device.device_type.model, self.puppetdb_models[device.name]
                    ),
                )
            else:
                success += 1

        self.log_success(None, "{} devices have matching model names".format(success))

    def test_puppetdb_vms_in_netbox(self):
        """Check that all PuppetDB VMs are in Netbox VMs."""
        vms = list(VirtualMachine.objects.exclude(status=DEVICE_STATUS_OFFLINE).values_list("name", flat=True))
        success = 0

        for device, is_virtual in self.puppetdb_devices.items():
            if not is_virtual:
                continue

            if device not in vms:
                self.log_failure(None, "missing VM from Netbox: {} ".format(device))
            else:
                success += 1

        self.log_success(None, "{} VMs that are in PuppetDB are also in Netbox VMs".format(success))

    def test_netbox_vms_in_puppetdb(self):
        """Check that all Netbox VMs are in PuppetDB VMs."""

        vms = VirtualMachine.objects.exclude(status=DEVICE_STATUS_OFFLINE)

        success = 0
        for vm in vms:
            if vm.name not in self.puppetdb_devices:
                self.log_failure(vm, "missing VM from PuppetDB")
            elif not self.puppetdb_devices[vm.name]:
                self.log_failure(vm, "expected VM marked as Physical in PuppetDB")
            else:
                success += 1

        self.log_success(None, "{} VMs that are in Netbox are also in PuppetDB VMs".format(success))
