"""Validator class for the Poweroutlet model."""

from extras.validators import CustomValidator


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance):
        """Mandatory entry point"""
        # Name
        if not str(instance.name).isdigit():
            self.fail("Invalid name (must be a non-negative integer)", field="name")
