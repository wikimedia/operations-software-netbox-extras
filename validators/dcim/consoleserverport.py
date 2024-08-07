"""Validator class for the Consoleserverport model."""

import re

from extras.validators import CustomValidator


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance, request) -> None:  # noqa: unused-argument
        """Mandatory entry point"""
        # Name
        if not re.search(r"^port\d{1,2}$", instance.name):
            self.fail("Invalid name (must start with 'port' followed by digits)", field="name")
