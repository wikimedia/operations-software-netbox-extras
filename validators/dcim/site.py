"""Validator class for the Site model."""

from extras.validators import CustomValidator


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance, request):  # noqa: unused-argument
        """Mandatory entry point"""
        # Slug
        if len(instance.slug) != 5:
            self.fail("Invalid slug (must be 5 chars)", field="slug")
        if instance.slug != instance.slug.lower():
            self.fail("Invalid slug (must be lowercase)", field="slug")
