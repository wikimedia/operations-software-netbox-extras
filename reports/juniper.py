"""
Checks the consistency of Netbox data against a csv export of the my.juniper.net installed base.
And the other way around.

"""

import csv
from collections import OrderedDict

from dcim.constants import DEVICE_STATUS_DECOMMISSIONING, DEVICE_STATUS_OFFLINE
from dcim.models import Device, InventoryItem
from extras.reports import Report

# Status we are fine not having support on
STATUS_IGNORE = (DEVICE_STATUS_OFFLINE, DEVICE_STATUS_DECOMMISSIONING)

PRODUCT_NAMES_IGNORE = [
    "JNP-QSFP-40G-LX4",  # optic
    "QFX-QSFP-40G-SR4",  # optic
    "S-MX104-ADV-R2",  # License
    "S-MX104-UPG-4X10GE",  # License
]

CSVFILE = "/tmp/juniper_installed_base.csv"


class Juniper(Report):
    description = """
    Checks the consistency of Netbox data against a csv export of the my.juniper.net installed base.
    And the other way around.
    """

    def __init__(self, *args, **kwargs):
        """Loads the CSV."""

        self.installed_base = self.load_installed_base()

        super().__init__(*args, **kwargs)

    @staticmethod
    def load_installed_base():
        installed_base = OrderedDict()
        full_csv = []

        try:
            with open(CSVFILE, newline="") as csvfile:
                full_csv = list(csv.reader(csvfile, delimiter=","))
        except IOError:
            return None

        column_names = full_csv[0]

        for row in full_csv[1:]:
            # Remove some /t from values
            row = [x.strip() for x in row]
            asset = dict(zip(column_names, row))
            # skip items without a serial number
            if asset["Serial #"] == "":
                continue

            # Ignore licenses
            if "-LIC" in asset["Product Name"]:
                continue

            # Ignore DACs
            if "-DAC-" in asset["Product Name"]:
                continue

            # Ignore DACs serials
            if asset["Product Name"] in PRODUCT_NAMES_IGNORE:
                continue

            installed_base[asset["Serial #"]] = asset

        return installed_base

    def test_missing_device_from_installed_base(self):
        if not self.installed_base:
            self.log_failure(None, "Can't load CSV file from {}".format(CSVFILE))
            return
        juniper_devices = (
            Device.objects.exclude(serial__isnull=True)
            .exclude(serial="")
            .exclude(status__in=STATUS_IGNORE)
            .filter(device_type__manufacturer__slug="juniper")
        )

        device_matches = 0
        for device in juniper_devices:
            if device.serial not in self.installed_base:
                self.log_failure(
                    device,
                    "Device with s/n {serial} not present in Juniper Installed Base".format(serial=device.serial),
                )
            else:
                device_matches += 1

        if device_matches:
            self.log_success(None, "{} devices matched".format(device_matches))

    def test_missing_inventory_from_installed_base(self):
        if not self.installed_base:
            self.log_failure(None, "Can't load CSV file from {}".format(CSVFILE))
            return
        parents = (
            Device.objects.values_list("pk", flat=True)
            .filter(device_type__manufacturer__slug="juniper")
            .exclude(status__in=STATUS_IGNORE)
        )

        juniper_inventory = (
            InventoryItem.objects.exclude(serial__isnull=True)
            .exclude(serial="")
            .filter(device_id__in=parents, manufacturer__slug="juniper")
        )

        device_matches = 0
        for inventory_item in juniper_inventory:
            if inventory_item.serial not in self.installed_base:
                self.log_failure(
                    inventory_item,
                    "{parent_name} item {part_id} with s/n {serial} not present in Juniper Installed Base".format(
                        parent_name=inventory_item.device.name,
                        part_id=inventory_item.part_id,
                        serial=inventory_item.serial,
                    ),
                )
            else:
                device_matches += 1

        if device_matches:
            self.log_success(None, "{} inventory items matched".format(device_matches))

    def test_consistency(self):
        if not self.installed_base:
            self.log_failure(None, "Can't load CSV file from {}".format(CSVFILE))
            return
        juniper_devices = (
            Device.objects.exclude(serial__isnull=True)
            .exclude(serial="")
            .filter(device_type__manufacturer__slug="juniper")
        )
        juniper_inventory = (
            InventoryItem.objects.exclude(serial__isnull=True).exclude(serial="").filter(manufacturer__slug="juniper")
        )
        devices = {}
        for device in juniper_devices:
            devices[device.serial] = device

        inventory_items = {}
        for item in juniper_inventory:
            inventory_items[item.serial] = item

        serial_matches = address_matches = support_matches = 0
        for serial, asset in self.installed_base.items():
            is_inventory_item = False
            name = asset["Product Name"]
            try:
                device = devices[serial]
            except KeyError:
                try:
                    inventory_items[serial]
                    is_inventory_item = True
                except KeyError:

                    self.log_failure(
                        None, "Device {name} with s/n {serial} not present in Netbox".format(name=name, serial=serial)
                    )
                    continue

            # TODO: check city/support of inventory items
            if not is_inventory_item:
                # TODO: Only use the cities to check if the "intalled at" is correct
                city = asset["Install City"].lower()
                if city not in device.site.physical_address.lower():
                    self.log_failure(
                        device,
                        "City missmatch: {city} (Juniper) vs. {netbox_address} (Netbox)".format(
                            city=city, netbox_address=device.site.physical_address
                        ),
                    )
                else:
                    address_matches += 1

                active_support = True if asset["Status"] == "Active" else False
                support_end_date = asset["Contract End Date"]
                if device.status not in STATUS_IGNORE and not active_support and support_end_date != "":
                    self.log_failure(
                        device,
                        "Support missing, ended on: {support_end_date}".format(support_end_date=support_end_date),
                    )
                else:
                    support_matches += 1

            serial_matches += 1

        if serial_matches or support_matches or address_matches:
            self.log_success(
                None,
                "{} matching serials; {} matching addresses; {} matching support".format(
                    serial_matches, address_matches, support_matches
                ),
            )
