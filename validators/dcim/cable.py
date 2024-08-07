"""Validator class for the Cable model."""

from circuits.models import CircuitTermination
from dcim.choices import LinkStatusChoices
from dcim.models import Cable, Interface
from extras.validators import CustomValidator

CORE_SITES = ("eqiad", "codfw")


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance: Cable, request) -> None:  # noqa: unused-argument
        """Mandatory entry point"""
        # label
        if instance.label:
            for cable_same_serial in Cable.objects.filter(label=instance.label):
                if instance.id and cable_same_serial.id == instance.id:
                    continue
                if self._get_site_slug(cable_same_serial) == self._get_site_slug(instance):
                    self.fail(f"Duplicate label with {cable_same_serial}", field="label")
        # Allow blank cables in core sites
        if (
            (not instance.label or not instance.label.strip())
            and not self._core_site_server(instance)
            and not instance.status == LinkStatusChoices.STATUS_PLANNED
        ):
            self.fail("Invalid label (must not be blank)", field="label")

        # Multiple connected endpoints
        # Our automation only supports cables with a single termination on each side
        if len(instance.a_terminations) > 1 or len(instance.b_terminations) > 1:
            self.fail("Our automation doesn't support cables with multiple endpoints")

    def _get_site_slug(self, cable: Cable) -> str:
        """Get a representative site slug given a cable.

        Since cables do not have their own site objects, we need to get it from a subsidiary object, which,
        depending on the termination type, may be on the termination object or the device object in the termination.
        """
        # can't do cable.terminations.all() at validation time :(
        for termination in list(cable.a_terminations) + list(cable.b_terminations):
            if isinstance(termination, CircuitTermination):
                return termination.site.slug
            if isinstance(termination, Interface):
                return termination.device.site.slug
        self.fail("Error: unable to find cable's site")
        return ''  # to make pylint happy, but this stops above

    def _core_site_server(self, cable: Cable) -> bool:
        """Check if the cable is a core site server cable.

        Arguments:
            cable: Netbox cable
        Returns:
            true: the cable is a core site server cable.
            false: it's not.

        """
        for termination in list(cable.a_terminations) + list(cable.b_terminations):
            if (
                isinstance(termination, Interface)
                and termination.device.role.slug == "server"
                and termination.device.site.slug in CORE_SITES
            ):
                return True
        return False
