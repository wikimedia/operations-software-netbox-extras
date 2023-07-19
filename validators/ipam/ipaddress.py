import re

from extras.validators import CustomValidator


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance):
        """Mandatory entry point"""
        # dns_name
        if len(instance.dns_name) > 255:
            self.fail(f'Invalid DNS name: too long ({len(instance.dns_name)})')

        if instance.dns_name:  # Accept empty values when there is no FQDN set
            if instance.dns_name.endswith("."):
                self.fail("Invalid DNS name: must not end with a dot")

            if "." not in instance.dns_name:
                self.fail("Invalid DNS name: no dot found, it must be an FQDN, not a hostname")

            if getattr(instance.assigned_object, 'name', None) == 'mgmt' and instance.dns_name.split('.')[1] != 'mgmt':
                self.fail("Invalid DNS name: '.mgmt.' must be present when assigned to a mgmt interface")

            allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
            if not all(allowed.match(x) for x in instance.dns_name.split(".")):
                self.fail("Invalid DNS name: must be a valid FQDN")
