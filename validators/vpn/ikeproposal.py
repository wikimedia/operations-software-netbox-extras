"""Validator class for the IKEProposal models"""

from extras.validators import CustomValidator


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance, request) -> None:  # noqa: unused-argument
        """Mandatory entry point"""
        # Ensure encryption algorithm is AES-GCM
        if not instance.encryption_algorithm.endswith("-gcm"):
            self.fail("Encryption algorithm must be AES in GCM mode.")
        # Ensure no authentication algorithm is set (not needed in GCM mode):
        if instance.authentication_algorithm:
            self.fail("No authentication algorithm should be configured with AES-GCM.")
        # Ensure one of the higher MODP groups or EC is used:
        if instance.group < 14:
            self.fail("DH Group must be 14 or higher.")
