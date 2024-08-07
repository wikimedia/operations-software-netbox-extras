"""Validator class for the Consoleport model."""

from extras.validators import CustomValidator

ALLOWED_NAMES = ("console0", "console-re0", "console-re1")


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance, request) -> None:  # noqa: unused-argument
        """Mandatory entry point"""
        # Name
        if instance.name not in ALLOWED_NAMES:
            self.fail(f"Invalid name (must be one of {ALLOWED_NAMES})", field="name")
