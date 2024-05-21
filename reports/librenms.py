"""Report parity errors between LibreNMS and Netbox."""
import configparser
import pymysql

from functools import lru_cache

from django.db.models import Q

from dcim.choices import DeviceStatusChoices
from dcim.models import Device, InventoryItem
from extras.reports import Report

CONFIG_FILE = "/etc/netbox/reports.cfg"

# Netbox system states to check.
INCLUDE_STATUSES = (
    DeviceStatusChoices.STATUS_ACTIVE,
    DeviceStatusChoices.STATUS_STAGED,
)

# Netbox roles to check (slugs)
# These are checked against the devices we get from LibreNMS
INCLUDE_DEVICE_ROLES_LNMS_CHECK = (
    "asw",
    "msw",
    "cr",
    "mr",
    "pfw",
    "pdu",
    "scs",
    "cloudsw",
)
# These are used in every other check (the above minus scs which report incorrectly
# in LibreNMS for serial numbers and device types.
INCLUDE_DEVICE_ROLES = ("asw", "msw", "cr", "mr", "pfw", "pdu", "cloudsw")

# Sites to exclude
EXCLUDE_SITES = ()

# Query filters for excluding certain models that don't seem to report correctly to LibreNMS or are unmanaged.
MODEL_EXCLUDES = Q()

INVENTORY_EXCLUDES = Q(name="FPM Board")

INVENTORY_ROLES_EXCLUDES = ("license",)


# These are very specific filters for devices that act incorrectly in LibreNMS. We should document them
# here as well.
#
# srx1500 with name pf3b does not report its serials in a way consistent with other similar devices.
#
DEVICE_EXCLUDES = Q(device_type__slug="srx1500", name__contains="pfw3b")

# The slugs for manufacturers that may also match with inventory items by serial
INVENTORY_MANUFACTURERS = ("juniper",)

# Some minor hacks for inventory items (keyed by netbox 'vendor " " model')
MODEL_EQUIVS_INVENTORY = {"juniper ex4300-48t": "juniper routing engine"}

# See T331519
MODEL_EQUIVS_DEVICES = {
    "qfx5120-48y-afi": "jnp48y8c-chas",
    "qfx5120-48y-afi2": "jnp48y8c-chas",
    "qfx5120-32c-afi": "qfx5120-32c",
    "qfx5120-32c-afi2": "qfx5120-32c",
}


class LibreNMSData:
    """This is a wrapper for the LibreNMS database which does some preprocessing of the return values."""

    def __init__(self, host, port, user, password, database):
        """Populate internal state from the LibreNMS database given MySQL connection parameters."""
        connection = pymysql.connect(
            host=host, port=int(port), user=user, password=password, database=database
        )

        self.device_duplicates = {}
        self.inventory_duplicates = {}
        self.devices = {}
        self.inventory = {}
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            # populate devices list by serial
            cursor.execute(
                """SELECT device_id as id,
                          lower(hardware) as hardware,
                          lower(sysDescr) as description,
                          serial,
                          hostname
                   FROM devices
                   WHERE serial IS NOT NULL
                     AND serial NOT IN ("", "N/A")
                     AND `ignore` = 0;"""
            )
            for device in cursor.fetchall():
                if not device["hardware"]:
                    # Unexpectedly, some devices will return an null for hardware.
                    device["hardware"] = "UNKNOWN"
                # Juniper hardware column sometimes has nodeN at the start.
                if device["hardware"].startswith("node"):
                    device["hardware"] = device["hardware"].split(" ", 1)[1]

                if device["serial"] in self.devices:
                    self.device_duplicates.setdefault(device["serial"], 1)
                    self.device_duplicates[device["serial"]] += 1

                self.devices[device["serial"]] = device
            # populate inventory list by serial
            cursor.execute(
                """SELECT entPhysical_id as id,
                          lower(entPhysicalDescr) as description,
                          entPhysicalSerialNum as serial,
                          lower(entPhysicalName) as model,
                          lower(entPhysicalVendorType) as vendor
                   FROM entPhysical
                   WHERE entPhysicalSerialNum IS NOT NULL
                         AND entPhysicalSerialNum NOT IN ("", "BUILTIN");"""
            )
            for inventory_item in cursor.fetchall():
                if inventory_item["serial"] in self.inventory:
                    # Unlikely situation that two devices have the same serial number
                    self.inventory_duplicates.setdefault(inventory_item["serial"], 1)
                    self.inventory_duplicates[inventory_item["serial"]] += 1

                # Some serials in inventory items have a S/N as their first token.
                if inventory_item["serial"].startswith("S/N "):
                    inventory_item["serial"] = inventory_item["serial"].split(" ", 1)[1]
                self.inventory[inventory_item["serial"]] = inventory_item


class LibreNMS(Report):
    description = __doc__

    def __init__(self, *args, **kwargs):
        self._device_query = Device.objects.filter(status__in=INCLUDE_STATUSES)
        super().__init__(*args, **kwargs)

    @property
    @lru_cache(maxsize=None)
    def librenms(self):
        """Load the data from the endpoint as needed by the reports."""
        configfile = configparser.ConfigParser()
        configfile.read(CONFIG_FILE)
        config = configfile["librenms"]
        return LibreNMSData(
            config["dbhost"],
            config["dbport"],
            config["user"],
            config["password"],
            config["database"],
        )

    def test_nb_net_in_librenms(self):
        """Check that every Device in the asw, pfw, msw, and cr classes in Netbox are `devices` in LibreNMS,
        matched by serial number.

        pfw is treated specially because the non-master nodes do not exist as a separate device in LibreNMS `devices`
           table, and is thus is excluded.

        Juniper devices are treated specially because the non-master nodes only appear in the entPhysical table.

        msw from Netgear do not appear in LibreNMS and are excluded.
        """

        success = 0
        no_ip = 0
        for dev in (
            self._device_query.filter(device_role__slug__in=INCLUDE_DEVICE_ROLES)
            .exclude(MODEL_EXCLUDES)
            .exclude(serial__exact="")
            .exclude(DEVICE_EXCLUDES)
        ):
            if (dev.serial in self.librenms.devices) or (
                (dev.device_type.manufacturer.slug in INVENTORY_MANUFACTURERS)
                and (dev.serial in self.librenms.inventory)
            ):
                success += 1

            elif dev.site.slug not in EXCLUDE_SITES:
                if not dev.primary_ip:
                    no_ip += 1
                else:
                    self.log_failure(
                        dev,
                        f"missing Netbox device from LibreNMS of role {dev.device_role.slug}",
                    )

        if no_ip:
            self.log_info(
                None, f"{no_ip} Netbox devices with no IP and not in LibreNMS"
            )
        self.log_success(None, f"{success} Netbox devices in LibreNMS")

    def test_nb_inventory_in_librenms(self):
        """Check that every InventoryItem attached to a Device in Netbox, is in `entPhysical` table in librenms, matched
        by serial number."""
        success = 0
        parents = self._device_query.values_list("pk", flat=True).filter(
            device_role__slug__in=INCLUDE_DEVICE_ROLES
        )
        for inventory_item in (
            InventoryItem.objects.filter(device_id__in=parents)
            .exclude(serial__isnull=True)
            .exclude(serial="")
            .exclude(role__slug__in=INVENTORY_ROLES_EXCLUDES)
            .exclude(INVENTORY_EXCLUDES)
        ):
            if (
                inventory_item.serial not in self.librenms.inventory
                and inventory_item.device.site.slug not in EXCLUDE_SITES
            ):
                self.log_failure(
                    inventory_item, "missing Netbox inventory item from LibreNMS"
                )
            else:
                success += 1

        self.log_success(None, f"{success} Netbox inventory items in LibreNMS")

    def test_librenms_in_nb(self):
        """Check that every `device` in LibreNMS exists as a Device in Netbox, matched by serial number."""
        success = 0
        devserials = self._device_query.filter(
            device_role__slug__in=INCLUDE_DEVICE_ROLES_LNMS_CHECK
        ).values_list("serial", flat=True)
        for serial, device in self.librenms.devices.items():
            if serial not in devserials:
                self.log_failure(
                    None,
                    "missing LibreNMS device from Netbox: serial: {} hostname: {} id: {}".format(
                        serial, device["hostname"], device["id"]
                    ),
                )
            else:
                success += 1

        self.log_success(None, f"{success} LibreNMS devices in Netbox")

    def test_librenms_vendor_model(self):
        """Check that every device from Netbox in LibreNMS has matchable hardware+manufacturer information.

        We have to do some manipulation, and we can match against LibreNMS"s `device` `sysDescr` or `hardware`
        or `entPhysical` `entPhysicalModelName` and `entPhysicalVendorType`.

        This 'in' for comparison because several of these fields have extra information, model number
        details and other things at the end of the string which are not relevant to this test (in an effort to be
        as general a check as possible without special exceptions).
        """
        success = 0
        for device in self._device_query.filter(
            device_role__slug__in=INCLUDE_DEVICE_ROLES
        ).exclude(MODEL_EXCLUDES):
            nb_vendor_string = str(device.device_type.manufacturer).lower()
            nb_model_string = str(device.device_type.model).lower()
            nb_vendor_model_string = " ".join((nb_vendor_string, nb_model_string))
            # Either the hardware or description has both the vendor and the model, discretely.
            if device.serial in self.librenms.devices:
                lnms_device_hardware = self.librenms.devices[device.serial]["hardware"]
                lnms_device_description = self.librenms.devices[device.serial][
                    "description"
                ]
                # The replace it to make server_technology match with "server technology" in NB.
                lnms_device_harddesc = (
                    lnms_device_hardware.replace('_', ' ') + " " + lnms_device_description
                )
                if nb_vendor_string in lnms_device_harddesc and (
                    nb_model_string in lnms_device_harddesc
                    or MODEL_EQUIVS_DEVICES.get(nb_model_string, "BADMATCH")
                    in lnms_device_harddesc
                ):
                    success += 1
                elif device.site.slug not in EXCLUDE_SITES:
                    self.log_failure(
                        device,
                        (
                            "mismatch between LibreNMS and Netbox device types: Netbox: {} (vendor model), "
                            "LibreNMS: {} (description) || {} (hardware)"
                        ).format(
                            nb_vendor_model_string,
                            self.librenms.devices[device.serial]["description"],
                            self.librenms.devices[device.serial]["hardware"],
                        ),
                    )
            elif device.serial in self.librenms.inventory:
                librenms_vendor_model_string = (
                    self.librenms.inventory[device.serial]["vendor"]
                    + " "
                    + self.librenms.inventory[device.serial]["model"]
                )
                if (
                    nb_vendor_model_string in librenms_vendor_model_string
                    or (
                        nb_vendor_string in librenms_vendor_model_string
                        and nb_model_string in librenms_vendor_model_string
                    )
                    or MODEL_EQUIVS_INVENTORY.get(nb_vendor_model_string, "BADMATCH")
                    in librenms_vendor_model_string
                ):
                    success += 1
                elif device.site.slug not in EXCLUDE_SITES:
                    self.log_failure(
                        device,
                        (
                            "mismatch between LibreNMS and Netbox inventory; Netbox: {} (vendor model), "
                            "LibreNMS: {} (vendor model)"
                        ).format(nb_vendor_model_string, librenms_vendor_model_string),
                    )

        self.log_success(
            None, f"{success} LibreNMS hardware and manufacturer matches in Netbox"
        )
