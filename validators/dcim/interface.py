"""Validator class for the Interface model."""

import re

from typing import Optional

from dcim.choices import InterfaceTypeChoices
from dcim.models import Interface
from extras.validators import CustomValidator
from ipam.models import VLAN
from netbox.context import current_request
from django.core.exceptions import ObjectDoesNotExist

NETWORK_ROLES = ("asw", "cr", "mr", "pfw", "cloudsw")

# For ergonomics the regexps that match interface names are placed in this tuple.
INTERFACES_REGEXP = re.compile(
    (
        r"|".join(
            (
                r"^fxp\d-re\d$",  # routing engine management
                r"^[a-z]{2}-\d+/\d+/\d+(:\d+){0,1}(\.\d+){0,1}$",  # Juniper (eg et-0/0/0:0.0)
                r"^vcp-\d+/\d+/\d+$",  # Juniper legacy (eg vcp-0/0/0)
                r"^[a-z]{1,4}(\d+){0,1}(\.\d+){0,1}$",  # typical device names (eg. eth0, vlan.900, etc)
                r"^\d+$",  # Netgear switch (just numbers)
                r"^ethernet-1/\d+(\.\d+){0,1}$",  # Nokia 7220 (i.e. ethernet-1/47, ethernet-1/47.100)
            )
        )
    )
)

TRIDENT3_TOR = ("qfx5120-48y-afi", "qfx5120-48y-afi2", "7220-ixr-d2l")
VIRTUAL_TYPES = (
    InterfaceTypeChoices.TYPE_VIRTUAL,
    InterfaceTypeChoices.TYPE_BRIDGE,
    InterfaceTypeChoices.TYPE_LAG,
)

NOKIA_PORT_BLOCKS = [
    (1, 2, 3, 6),
    (4, 5, 7, 9),
    (8, 10, 11, 12),
    (13, 14, 15, 18),
    (16, 17, 19, 21),
    (20, 22, 23, 24),
    (25, 26, 27, 30),
    (28, 29, 31, 33),
    (32, 34, 35, 36),
    (37, 38, 39, 42),
    (40, 41, 43, 45),
    (44, 46, 47, 48)
]


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def _check_trident3_port(self, instance: Interface) -> None:
        """Checks that the port speed is consistent with others in block due to Trident 3 constraint"""
        logical_port = int(instance.name.replace("Ethernet", "").split("/")[-1])
        if instance.device.device_type.manufacturer.slug == "juniper":
            # Regular port-block layout 0-3, 4-7, 8-11 etc.
            block_start = logical_port - (logical_port % 4)
            block_ports = range(block_start, block_start + 4)
            device_ints = Interface.objects.filter(
                device_id=instance.device.id, enabled=True, mgmt_only=False
            ).exclude(type__in=VIRTUAL_TYPES).exclude(id=instance.id)
            # The exclude "id=instance.id" is to prvent an error between an interface and itself
            # For example when changing the type of an interface
            for device_int in device_ints:
                # Get logical port number from interface name
                try:
                    port_num = int(device_int.name.replace("Ethernet", "").split("/")[-1])
                except ValueError:
                    # Don't block the user if there is an improperly named interface on the switch
                    continue
                if port_num <= 47 and port_num in block_ports and device_int.type != instance.type:
                    self.fail(
                        f"Invalid type/speed '{instance.type}' (must be {device_int.type} "
                        f"to match {device_int.name} within the same block)", field="type"
                    )
        elif instance.device.device_type.manufacturer.slug == "nokia":
            # Wonky Nokia port-block layout
            teng_compat = ['1000base-x-sfp', '10gbase-x-sfpp']
            compatible_types = teng_compat if instance.type in teng_compat else [instance.type]
            for port_block in NOKIA_PORT_BLOCKS:
                if logical_port in port_block:
                    block_int_names = [f"ethernet-1/{port}" for port in port_block if port != logical_port]
                    block_ints = Interface.objects.filter(
                        device_id=instance.device.id, enabled=True, name__in=block_int_names
                    )
                    for block_int in block_ints:
                        if block_int.type not in compatible_types:
                            self.fail(
                                f"Type/speed '{instance.type}' is incompatible with {block_int.name} "
                                f"('{block_int.type}') in the same block of four", field="type"
                            )
                    break

    def validate(self, instance: Interface, request: Optional[current_request]) -> None:  # noqa: unused-argument
        """Mandatory entry point"""
        # Ignore all the non-network devices interfaces
        if instance.device.role.slug not in NETWORK_ROLES:
            return

        # Name
        if not INTERFACES_REGEXP.fullmatch(instance.name):
            self.fail("Invalid name (must match the INTERFACES_REGEXP options)", field="name")

        # Validate IRB interface names are valid, i.e. correspond to an actual vlan
        if instance.name.startswith("irb") and instance.name not in ("irb", "irb0"):
            try:
                vid = int(instance.name.split(".")[1])
                VLAN.objects.get(vid=vid, site=instance.device.site.id)
            except (ValueError, ObjectDoesNotExist):
                self.fail("IRB interface invalid - does not match vlan at this site.", field="name")

        # MTU
        if (
            instance.connected_endpoints
            and isinstance(instance.connected_endpoints[0], Interface)
            and instance.mtu not in (9000, 9192)  # Ignore good MTU (NTT VPLS is 9000 max.)
            and not instance.lag  # Ignore LAG members
            and not (
                instance.device.tenant and instance.device.tenant.slug == "fr-tech"
            )  # Ignore frack devices
            and instance.enabled  # Ignore disabled interfaces
            and not instance.mgmt_only  # Ignore mgmt interfaces
            and not str(instance.name).startswith("vcp-")  # Ignore VC links
        ):
            self.fail(f"Invalid MTU {instance.mtu}, must be 9192", field="mtu")

        # Attributes
        attributes = [
            "description",
            "lag",
            "mtu",
            "mode",
            "mac_address",
            "count_ipaddresses",
        ]
        if (
            "no-mon"
            not in str(instance.description)  # doesn't have "no-mon" in description
            and not instance.enabled  # disabled interface
        ):
            for attribute in attributes:
                # Workaround bug T310590#8851738
                # At creation time, count_ipaddresses is briefly at 246 then goes back to 0
                if attribute == "count_ipaddresses" and not instance.id:
                    continue
                if getattr(instance, attribute):
                    self.fail(f"Invalid {attribute} (must not be set on disabled interfaces)",
                              field=attribute if attribute != "count_ipaddresses" else None)
        # Trident 3 switches ports blocks
        if (
            instance.type not in VIRTUAL_TYPES
            and not instance.mgmt_only
            and instance.device.device_type.slug in TRIDENT3_TOR
        ):
            self._check_trident3_port(instance)

        # child interfaces must be virtual
        if instance.parent and (instance.type not in VIRTUAL_TYPES):
            self.fail(f"Child interfaces must be one of those types: {VIRTUAL_TYPES}.", field="type")
