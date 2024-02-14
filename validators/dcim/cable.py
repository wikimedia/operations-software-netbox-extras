"""Validator class for the Cable model."""

from django.contrib.contenttypes.models import ContentType

from dcim.choices import LinkStatusChoices
from dcim.models import Cable, Interface
from extras.validators import CustomValidator

CORE_SITES = ("eqiad", "codfw")

interface_ct = ContentType.objects.get_for_model(Interface)


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance):
        """Mandatory entry point"""
        # label
        if instance.label:
            try:
                cable_same_serial = Cable.objects.get(label=instance.label)
            except Cable.DoesNotExist:
                return
            if instance.id and cable_same_serial.id == instance.id:
                return
            if self._get_site_slug(cable_same_serial) == self._get_site_slug(instance):
                self.fail(f"Duplicate label with {cable_same_serial}")
        # Allow blank cables in core sites
        if (
            (not instance.label or not instance.label.strip())
            and not self._core_site_server(instance)
            and not instance.status == LinkStatusChoices.STATUS_PLANNED
        ):
            self.fail("Invalid label (must not be blank)")

    def _get_site_slug(self, cable):
        """Get a representative site slug given a cable.

        Since cables do not have their own site objects, we need to get it from a subsidiary object, which,
        depending on the termination type, may be on the termination object or the device object in the termination.
        """
        if (
            cable.termination_a_type.name == "circuit termination"
            and cable.termination_a.site
        ):
            return cable.termination_a.site.slug
        if cable.termination_a.device and cable.termination_a.device.site:
            return cable.termination_a.device.site.slug
        self.fail("Error: unable to find cable's site")
        return None  # to make pylint happy, but this stops above

    def _core_site_server(self, cable):
        """check if the cable is a core site server cable.

         Arguments:
            cable: Netbox cable
        Returns:
            true: the cable is a core site server cable.
            false: it's not.
        """
        if (
            cable.termination_a_type == interface_ct
            and cable.termination_a.device.device_role.slug == "server"
            and cable.termination_a.device.site.slug in CORE_SITES
        ):
            return True
        if (
            cable.termination_b_type == interface_ct
            and cable.termination_b.device.device_role.slug == "server"
            and cable.termination_b.device.site.slug in CORE_SITES
        ):
            return True
        return False
