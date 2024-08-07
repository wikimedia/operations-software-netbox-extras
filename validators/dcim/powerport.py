"""Validator class for the Powerport model."""

from extras.validators import CustomValidator

ALLOWED_NAMES = ("PEM 0", "PEM 1", "Power Supply 0", "Power Supply 1", "PSU1", "PSU2")


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance, request) -> None:  # noqa: unused-argument
        """Mandatory entry point"""
        # Name
        if instance.name not in ALLOWED_NAMES:
            self.fail(f"Invalid name (must be one of {ALLOWED_NAMES})", field="name")
