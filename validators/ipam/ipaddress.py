from extras.validators import CustomValidator

from validators import domain


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance):
        """Mandatory entry point"""
        # dns_name
        if instance.dns_name.endswith("."):
            self.fail("Invalid DNS name (must not end with a dot)")
        if not domain(instance.dns_name):
            self.fail("Invalid DNS name (must be a FQDN)")
