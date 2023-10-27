import configparser
import json

import requests

from django.core.exceptions import ObjectDoesNotExist

from _common import Importer, CONFIGFILE

from dcim.models import Device
from extras.scripts import BooleanVar, Script, StringVar, TextVar
from virtualization.models import VirtualMachine


class ImportPuppetDB(Script, Importer):
    class Meta:
        name = "Import Interfaces, IPAddresses, Cables and switch ports from PuppetDB"
        description = "Access PuppetDB and resolve interface and IP address differences."
        commit_default = False

    device = StringVar(description="The device name(s) to import interface(s) for (space separated)",
                       label="Devices")

    def _validate_device(self, device):
        """Check if a device is OK to import from PuppetDB (overrides Importer's)"""
        if device.tenant:
            self.log_failure(f"{device} has non-null tenant {device.tenant} skipping.")
            return False
        return super()._validate_device(device)

    def _get_networking_facts(self, cfg, device):
        """Access PuppetDB for `networking`, `net_driver` and `lldp` facts."""
        # Get networking facts
        puppetdb_url = "/".join([cfg["puppetdb"]["url"], "v1/facts", "{}", device.name])
        response = requests.get(puppetdb_url.format("networking"), verify=cfg["puppetdb"]["ca_cert"])
        if response.status_code != 200:
            self.log_failure(f"Cannot retrieve PuppetDB `networking` facts about {device.name}")
            return None, None, None
        networking = response.json()
        # Get net_driver facts
        response = requests.get(puppetdb_url.format("net_driver"), verify=cfg["puppetdb"]["ca_cert"])
        if response.status_code != 200:
            self.log_failure(f"Cannot retrieve PuppetDB `net_driver` facts about {device.name}")
            return None, None, None
        net_driver = response.json()
        # Get lldp facts
        response = requests.get(puppetdb_url.format("lldp"), verify=cfg["puppetdb"]["ca_cert"])
        if response.status_code != 200:
            self.log_failure(f"Cannot retrieve PuppetDB `lldp` facts about {device.name}")
            return None, None, None
        lldp = response.json()
        return net_driver, networking, lldp

    def run(self, data, commit):
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
            self.log_info(f"Processing device {device}")
            if self._validate_device(device):
                net_driver, networking, lldp = self._get_networking_facts(cfg, device)
                if net_driver is None:
                    continue
                messages.extend(self._import_interfaces_for_device(device, net_driver, networking, lldp, False))
            self.log_info(f"{device} done.")
        for device in vmdevices:
            self.log_info(f"Processing virtual device {device}")
            net_driver, networking, lldp = self._get_networking_facts(cfg, device)
            if net_driver is None:
                continue
            messages.extend(self._import_interfaces_for_device(device, net_driver, networking, lldp, True))
            self.log_info(f"{device} done.")

        return "\n".join(messages)


class ImportNetworkFacts(Script, Importer):  # TODO is that used? can we delete it?
    class Meta:
        name = "Import Interfaces from a JSON blob"
        description = "Accept a JSON blob and resolve interface and IP address differences."
        commit_default = False

    device = StringVar(description="The device name to import interfaces and IP addresses for.",
                       label="Device")
    jsonblob = TextVar(description=("A JSON Dictionary with at least the `networking` key similar to what PuppetDB "
                                    "outputs. It may contain a `net_driver` key which specifies the speed of each"
                                    "interface, but the devices will take the default value if this is not specified."),
                       label="Facts JSON")
    statusoverride = BooleanVar(description=("Normally only hosts of specific status are considered for import, if "
                                             "this setting is set, the script will ignore the host's status."),
                                label="Status Override")

    def __init__(self, *args, **vargs):
        super().__init__(*args, **vargs)

    def _is_invalid_facts(self, facts):
        """We can very validate facts beyond this level, things will just explode if the facts are incorrect however."""
        if "networking" not in facts:
            self.log_failure(f"Can't find `networking` in facts JSON."
                             f"Keys in blob are: {list(facts.keys())}")
            return True
        if "net_driver" not in facts:
            self.log_warning("Can't find `net_driver` in facts JSON. Using default speed for all interfaces.")
            return True

    def run(self, data, commit):
        """Execute script as per Script interface."""
        facts = json.loads(data["jsonblob"])
        if self._is_invalid_facts(facts):
            return ""

        is_vm = False
        try:
            device = Device.objects.get(name=data["device"])
            if ((not data["statusoverride"]) and (not self._validate_device(device))):
                return ""
        except ObjectDoesNotExist:
            try:
                device = VirtualMachine.objects.get(name=data["device"])
                is_vm = True
            except ObjectDoesNotExist:
                self.log_failure(f"Not devices found by the name {data['device']}")
                return ""

        self.log_info(f"Processing device {device}")
        net_driver = {}
        if "net_driver" in facts:
            net_driver = facts["net_driver"]
        lldp = {}
        if "lldp" in facts:
            lldp = facts["lldp"]
        messages = self._import_interfaces_for_device(device, net_driver, facts["networking"], lldp, is_vm)
        self.log_info(f"{device} done.")

        return "\n".join(messages)
