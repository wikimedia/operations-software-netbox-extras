"""Report on various cable, port, and termination related errors.

BLOCKLISTS:
  test_blank_cable_label: eqiad
"""

import re

from django.contrib.contenttypes.models import ContentType

from dcim.choices import DeviceStatusChoices
from dcim.models import (
    Cable,
    CableTermination,
    ConsolePort,
    ConsoleServerPort,
    Interface,
    PowerPort,
)
from extras.reports import Report

# these are statuses for devices that we care about
EXCLUDE_STATUSES = (
    DeviceStatusChoices.STATUS_DECOMMISSIONING,
    DeviceStatusChoices.STATUS_INVENTORY,
    DeviceStatusChoices.STATUS_OFFLINE,
    DeviceStatusChoices.STATUS_PLANNED,
)

interface_ct = ContentType.objects.get_for_model(Interface)


class Cables(Report):
    """Report on various cable-related errors."""

    description = __doc__

    def _port_names_test(self, queryset: CableTermination, regex: re.Pattern, label: str) -> None:
        """Check that Cables and CableTermination have proper name.

        Test and report each item in the query set (presumed to be a CableTermination) for its name matching the
        compiled regular expression passed as regex.

        Arguments:
            queryset: A pre-filtered queryset of a CableTermination child.
            regex: A pre-compiled regular expression object to match the cable names against.
            label: A label to identify the cables with in log messages.

        """
        successes = 0
        for cable in queryset:
            if regex.match(cable.name):
                successes += 1
            else:
                dev = cable.device
                if dev is None:
                    self.log_failure(
                        None,
                        (
                            f"incorrectly named {label} cable termination not assigned to any device"
                            f"(interface id: {cable.id}): {cable.name}"
                        ),
                    )
                else:
                    self.log_failure(
                        cable.device,
                        f"incorrectly named {label} cable termination: {cable.name}",
                    )

        self.log_success(
            None, f"{successes} correctly named {label} cable terminations"
        )

    def test_console_port_termination_names(self) -> None:
        """Proxy to _port_names_test with values for checking console ports."""
        self._port_names_test(
            ConsolePort.objects.exclude(device__status__in=EXCLUDE_STATUSES),
            re.compile(r"console\d|console-re\d|serial\d"),
            "console port",
        )

    def test_console_server_port_termination_names(self) -> None:
        """Proxy to _port_names_test with values for checking console server ports."""
        self._port_names_test(
            ConsoleServerPort.objects.exclude(device__status__in=EXCLUDE_STATUSES),
            re.compile(r"port\d+"),
            "console server port",
        )

    def test_power_port_termination_names(self) -> None:
        """Proxy to _port_names_test with values for checking power ports."""
        self._port_names_test(
            PowerPort.objects.exclude(device__status__in=EXCLUDE_STATUSES),
            re.compile(r"PSU\d|PEM \d|Power Supply \d"),
            "power port",
        )

    def test_unterminated_cable(self) -> None:
        """All the cables should be connected on both sides."""
        successes = 0
        for cable in Cable.objects.all():
            if not cable.a_terminations or not cable.b_terminations:
                self.log_failure(cable, "Unterminated cable, should be connected on both sides.")
            else:
                successes += 1
        self.log_success(None, f"{successes} cables correctly connected.")
