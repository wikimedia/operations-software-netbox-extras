"""Several integrity/coherence checks against the data."""

from collections import Counter

from dcim.choices import DeviceStatusChoices
from dcim.models import Device, DeviceType, Site
from extras.reports import Report

# Network device roles for which we keep spares in inventory.
NETWORK_ROLES = ("asw", "cr", "mr", "pfw", "cloudsw", "msw")

# Statuses meaning a device type is still (or about to be) used in production.
IN_USE_STATUSES = (
    DeviceStatusChoices.STATUS_ACTIVE,
    DeviceStatusChoices.STATUS_PLANNED,
)

# Switch roles for which each site should keep at least one spare per device type.
SPARE_REQUIRED_ROLES = ("asw", "cloudsw", "msw")

# Sites where spares are expected to be stored.
SPARE_REQUIRED_SITES = ("eqiad", "codfw")

# Device type slugs not requiring a spare (e.g. models being phased out).
SPARE_EXCLUDED_DEVICE_TYPES = ("fs750t2",)


class Rack(Report):
    description = "Several integrity/coherence checks against the rack related data."

    def test_connected_unracked(self) -> None:
        """Determine if unracked boxes still have console connections marked as conneced."""
        for device in Device.objects.filter(rack=None):
            # TODO all cables, not just console
            consoleports = device.consoleports.all()
            good = True
            msgs = [
                f"connected console ports attached to unracked device {device.name}:"
            ]
            for port in consoleports:
                if port.cable:
                    msgs.append(port.name)
                    good = False
            if not good:
                self.log_failure(device, " ".join(msgs))


class NetworkSpares(Report):
    description = (
        "Check network spares: find inventory devices whose device type is no longer "
        "used at their site, and in-use switch types missing a spare at their site."
    )

    def test_unneeded_network_spares(self) -> None:
        """Flag inventory network devices with no active or planned device of the same type at their site."""
        # Single query: every (site, device type) pair with at least one active or planned device.
        in_use = set(
            Device.objects.filter(
                status__in=IN_USE_STATUSES,
                role__slug__in=NETWORK_ROLES,
            )
            .order_by()
            .values_list("site_id", "device_type_id")
            .distinct()
        )

        spares = (
            Device.objects.filter(
                status=DeviceStatusChoices.STATUS_INVENTORY,
                role__slug__in=NETWORK_ROLES,
            )
            .select_related("device_type__manufacturer", "role", "site")
            .order_by("site__slug", "device_type__model", "name")
        )

        needed = 0
        for device in spares:
            if (device.site_id, device.device_type_id) in in_use:
                needed += 1
                continue
            self.log_failure(
                device,
                (
                    f"{device.site.slug}: spare {device.device_type.model} "
                    "no active or planned device of this type, please set to OFFLINE"
                ),
            )

        self.log_success(
            None,
            f"{needed} spare network devices have an active or planned device of the same type at their site",
        )

    def test_missing_network_spares(self) -> None:
        """Flag site/device type pairs of in-use switches without any spare in inventory at that site."""
        # Number of active or planned switches per (site, device type).
        in_use = Counter(
            Device.objects.filter(
                status__in=IN_USE_STATUSES,
                role__slug__in=SPARE_REQUIRED_ROLES,
                site__slug__in=SPARE_REQUIRED_SITES,
            )
            .exclude(device_type__slug__in=SPARE_EXCLUDED_DEVICE_TYPES)
            .order_by()
            .values_list("site_id", "device_type_id")
        )

        # (site, device type) pairs having at least one device in inventory, whatever its role.
        spares = set(
            Device.objects.filter(
                status=DeviceStatusChoices.STATUS_INVENTORY,
                site__slug__in=SPARE_REQUIRED_SITES,
            )
            .order_by()
            .values_list("site_id", "device_type_id")
            .distinct()
        )

        sites = Site.objects.in_bulk({site_id for site_id, _ in in_use})
        device_types = DeviceType.objects.select_related("manufacturer").in_bulk(
            {type_id for _, type_id in in_use}
        )

        covered = 0
        for site_id, type_id in sorted(
            in_use, key=lambda key: (sites[key[0]].slug, device_types[key[1]].model)
        ):
            if (site_id, type_id) in spares:
                covered += 1
                continue
            device_type = device_types[type_id]
            self.log_failure(
                device_type,
                (
                    f"{sites[site_id].slug}: no spare for {in_use[(site_id, type_id)]} active/planned "
                    f"{device_type.model}, add an exception or set one to status INVENTORY"
                ),
            )

        self.log_success(
            None,
            f"{covered} site/device type pairs have at least one spare in inventory",
        )
