"""Validator class for the Interface model."""

import re

from extras.validators import CustomValidator

NETWORK_ROLES = ("asw", "cr", "mr", "pfw", "cloudsw")

# For ergonomics the regexps that match interface names are placed in this tuple.
INTERFACES_REGEXP = re.compile(
    (
        r"|".join(
            (
                r"^fxp\d-re\d$",  # routing engine management
                r"^[a-z]{2}-\d+/\d+/\d+(:\d+){0,1}(\.\d+){0,1}$",  # Juniper (eg et-0/0/0:0.0)
                r"^[a-z]{1,4}(\d+){0,1}(\.\d+){0,1}$",  # typical device names (eg. eth0, vlan.900, etc)
                r"^\d+$",  # Netgear switch (just numbers)
                r"^Ethernet\d+$",  # SONiC (eg. Ethernet1)
            )
        )
    )
)


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance):
        """Mandatory entry point"""
        # Name
        if (
            instance.device.device_role.slug in NETWORK_ROLES
            and not INTERFACES_REGEXP.fullmatch(instance.name)
        ):
            self.fail("Invalid name (must match the INTERFACES_REGEXP options)")

        # MTU
        if (
            hasattr(instance.connected_endpoint, "device")
            and instance.device.device_role.slug in NETWORK_ROLES  # Network devices
            and instance.mtu != 9192  # Ignore good MTU
            and not instance.lag  # Ignore LAG members
            and not (
                instance.device.tenant and instance.device.tenant.slug == "fr-tech"
            )  # Ignore frack devices
            and instance.enabled  # Ignore disabled interfaces
            and not str(instance.name).startswith("vcp-")
        ):  # Ignore VC links
            self.fail("Invalid MTU (must be 9192)")

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
            and instance.device.device_role.slug in NETWORK_ROLES
        ):  # network devices only
            for attribute in attributes:
                # Workaround bug T310590#8851738
                # At creation time, count_ipaddresses is briefly at 246 then goes back to 0
                if attribute == "count_ipaddresses" and not instance.id:
                    continue
                if getattr(instance, attribute):
                    self.fail(
                        f"Invalid {attribute} (must not be set on disabled interfaces)"
                    )
