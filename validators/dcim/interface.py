"""Validator class for the Interface model."""

from extras.validators import CustomValidator

NETWORK_ROLES = ("asw", "cr", "mr", "pfw", "cloudsw")


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance):
        """Mandatory entry point"""
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
                if getattr(instance, attribute):
                    self.fail(
                        f"Invalid {attribute} (must not be set on disabled interfaces)"
                    )
