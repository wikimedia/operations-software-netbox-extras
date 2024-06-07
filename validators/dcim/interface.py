"""Validator class for the Interface model."""

import re

from dcim.choices import InterfaceTypeChoices
from dcim.models import Interface
from extras.validators import CustomValidator
from ipam.models import VLAN
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
                r"^Ethernet\d+$",  # SONiC (eg. Ethernet1)
                r"^Loopback\d+$",  # SONiC (eg. Loopback0)
                r"^Management\d+$",  # SONiC (eg. Management0)
                r"^Vlan\d+$",  # SONiC (eg. Vlan1234)
            )
        )
    )
)

TRIDENT3_DEVICES = ("qfx5120-48y-afi", "qfx5120-48y-afi2", "powerswitch-s5248f-on")
VIRTUAL_TYPES = (
    InterfaceTypeChoices.TYPE_VIRTUAL,
    InterfaceTypeChoices.TYPE_BRIDGE,
    InterfaceTypeChoices.TYPE_LAG,
)


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def _check_trident3_port(self, instance: Interface) -> None:
        """Checks that the port speed is consistent with others in block due to Trident 3 constraint"""
        logical_port = int(instance.name.replace("Ethernet", "").split("/")[-1])
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

    def validate(self, instance, request):  # noqa: unused-argument
        """Mandatory entry point"""
        # Ignore all the non-network devices interfaces
        if instance.device.device_role.slug not in NETWORK_ROLES:
            return

        # Name
        if not INTERFACES_REGEXP.fullmatch(instance.name):
            self.fail("Invalid name (must match the INTERFACES_REGEXP options)", field="name")

        # Validate IRB interface names are valid, i.e. correspond to an actual vlan
        if instance.name.startswith("irb"):
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
            and instance.device.device_type.slug in TRIDENT3_DEVICES
        ):
            self._check_trident3_port(instance)
