import configparser

from typing import Union

import requests

from wmf_scripts_imports.common import Importer, CONFIGFILE

from dcim.models import Device
from extras.scripts import Script, StringVar
from virtualization.models import VirtualMachine


class ImportPuppetDB(Script, Importer):
    class Meta:
        name = "Import Interfaces, IPAddresses, Cables and switch ports from PuppetDB"
        description = "Access PuppetDB and resolve interface and IP address differences."
        commit_default = False  # noqa: unused-variable

    device = StringVar(description="The device name(s) to import interface(s) for (space separated)",
                       label="Devices")

    def _validate_device(self, device: Device) -> bool:
        """Check if a device is OK to import from PuppetDB (overrides Importer's)"""
        if device.tenant:
            self.log_failure(f"{device} has non-null tenant {device.tenant} skipping.", obj=device)
            return False
        return super()._validate_device(device)

    def _get_networking_facts(self, cfg: configparser.ConfigParser, device: Union[Device, VirtualMachine]):
        """Access PuppetDB for 'networking', 'net_driver' and 'lldp' facts."""
        # Get networking facts
        puppetdb_url = "/".join([cfg["puppetdb"]["url"], "v1/facts", "{}", device.name])
        response = requests.get(puppetdb_url.format("networking"), verify=cfg["puppetdb"]["ca_cert"], timeout=60)
        if response.status_code != 200:
            self.log_failure(f"Cannot retrieve PuppetDB 'networking' facts about {device.name}", obj=device)
            return None, None, None
        networking = response.json()
        # Get net_driver facts
        response = requests.get(puppetdb_url.format("net_driver"), verify=cfg["puppetdb"]["ca_cert"], timeout=60)
        if response.status_code != 200:
            self.log_failure(f"Cannot retrieve PuppetDB 'net_driver' facts about {device.name}", obj=device)
            return None, None, None
        net_driver = response.json()
        # Get lldp facts
        response = requests.get(puppetdb_url.format("lldp"), verify=cfg["puppetdb"]["ca_cert"], timeout=60)
        if response.status_code != 200:
            self.log_failure(f"Cannot retrieve PuppetDB 'lldp' facts about {device.name}", obj=device)
            return None, None, None
        lldp = response.json()
        return net_driver, networking, lldp

    def run(self, data: dict, commit: bool) -> str:  # noqa: unused-argument
        """Execute script as per Script interface."""
        cfg = configparser.ConfigParser()
        cfg.read(CONFIGFILE)

        devices = Device.objects.filter(name__in=data["device"].split())
        vmdevices = VirtualMachine.objects.filter(name__in=data["device"].split())
        messages = []
        if not devices and not vmdevices:
            message = "No Netbox devices found for specified list."
            self.log_failure(message)
            return message

        for device in devices:
            self.log_info(f"Processing baremetal device {device}", obj=device)
            if self._validate_device(device):
                net_driver, networking, lldp = self._get_networking_facts(cfg, device)
                if net_driver is None:
                    continue
                messages.extend(self._import_interfaces_for_device(device, net_driver, networking, lldp, False))
            self.log_info(f"{device} done.", obj=device)
        for device in vmdevices:
            self.log_info(f"Processing virtual device {device}", obj=device)
            net_driver, networking, lldp = self._get_networking_facts(cfg, device)
            if net_driver is None:
                continue
            messages.extend(self._import_interfaces_for_device(device, net_driver, networking, lldp, True))
            self.log_info(f"{device} done.", obj=device)

        return "\n".join(messages)
