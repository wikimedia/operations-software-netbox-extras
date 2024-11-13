"""Validator class for the IPSecPolicy model."""

from extras.validators import CustomValidator


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance, request) -> None:  # noqa: unused-argument
        """Mandatory entry point"""
        # Ensure we only define one proposal, i.e. allowed set of ciphers, for a policy.
        if instance.proposals.count() > 1:
            self.fail("Only use one proposal for any policy.")
        # Ensure one of the higher MODP groups or EC is used for PFS:
        if not instance.pfs_group or instance.pfs_group < 14:
            self.fail("DH Group must be defined for PFS and be 14 or higher.")
