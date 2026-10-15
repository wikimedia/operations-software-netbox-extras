"""Validator class for the Rack model."""

import re

from extras.validators import CustomValidator

from dcim.choices import RackStatusChoices

from dcim.models import Rack

FACILITY_ID_REGEX: dict[str, str] = {"eqiad": r"^[0-9]{6}\.[0-9]{4}$"}


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance: Rack, request) -> None:  # noqa: unused-argument
        """Mandatory entry point"""
        # Facility ID
        # Ignore non active racks
        if instance.status != RackStatusChoices.STATUS_ACTIVE:
            return

        regex = FACILITY_ID_REGEX.get(instance.site.slug)
        if not regex:
            if instance.facility_id:
                self.fail(f"Invalid facility ID (must be empty except for {FACILITY_ID_REGEX.keys()})",
                          field="facility_id")
            # Sites with no policy and no facility IDs set
            return

        if not instance.facility_id:
            self.fail("Facility ID is required for active racks at this site", field="facility_id")

        if not re.fullmatch(regex, instance.facility_id):
            self.fail(f"Invalid facility ID (must match regex {regex})", field="facility_id")

        duplicate = Rack.objects.filter(facility_id=instance.facility_id).exclude(pk=instance.pk).first()
        if duplicate:
            self.fail(f"Duplicate facility ID (already used by {duplicate})", field="facility_id")
