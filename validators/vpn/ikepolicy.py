"""Validator class for the IKEPolicy model."""

from extras.validators import CustomValidator


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance, request) -> None:  # noqa: unused-argument
        """Mandatory entry point"""
        # Ensure we only define one proposal, i.e. allowed set of ciphers, for a policy.
        if instance.proposals.count() > 1:
            self.fail("Only use one proposal for any policy.")
        # Make sure IKEv2 is used
        if instance.version != 2:
            self.fail("IKE version 2 must be used.")
