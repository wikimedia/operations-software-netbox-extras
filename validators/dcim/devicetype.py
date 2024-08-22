"""Validator class for the Devicetype model."""

import re

from django.utils.text import slugify

from extras.validators import CustomValidator

POWEREDGE_SLUG_RE = re.compile(r"^poweredge-r\d{3}\w{0,3}(-config\w+){0,1}$")


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance, request):  # noqa: unused-argument
        """Mandatory entry point"""
        # Only apply validator to Dell devices
        if instance.manufacturer.slug != 'dell':
            return
        # Name
        # Prevent slug typoes
        if not instance.slug == slugify(instance.model):
            self.fail(f"Invalid slug (must be {slugify(instance.model)})", field="slug")

        # Ignore non servers models
        if instance.slug.startswith(('storage', 'powerswitch')):
            return

        if not POWEREDGE_SLUG_RE.fullmatch(instance.slug):
            self.fail(f"Invalid model (slug must match {POWEREDGE_SLUG_RE})", field="model")
