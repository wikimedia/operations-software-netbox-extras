"""
Report on various cable, port, and termination related errors.

BLACKLISTS:
  test_blank_cable_label: eqiad
"""

import re

from collections import defaultdict

from django.contrib.contenttypes.models import ContentType

from dcim.choices import CableStatusChoices, DeviceStatusChoices

from dcim.models import Cable, ConsolePort, ConsoleServerPort, Interface, PowerPort, PowerOutlet
from extras.reports import Report

# these are statuses for devices that we care about
EXCLUDE_STATUSES = (
    DeviceStatusChoices.STATUS_DECOMMISSIONING,
    DeviceStatusChoices.STATUS_INVENTORY,
    DeviceStatusChoices.STATUS_OFFLINE,
    DeviceStatusChoices.STATUS_PLANNED,
)

# For ergonomics the regexps that match interface names are placed in this
# tuple. This is later joined with | to make the final regexp.
INTERFACES_REGEXP = (
    r"^mgmt\d?$|^ILO$|^i?DRAC$",  # managment interfaces
    r"^fxp\d-re\d$",  # routing engine management interfaces
    r"^[a-z]+-\d+/\d+/\d+(\.\d+){0,1}$",  # Juniper interfaces eg et-0/0/0
    r"^[a-z]{1,4}(\d+){0,1}(\.\d+){0,1}$",  # typical device names (eg eth0) and vlan.900 etc.
    r"^en(p\d+)?s\d+(f\d+)?((d|np)\d+)?$",  # systemd 'path' devices
    r"^cali[a-f0-9]+",  # kubernetes calico interfaces
    r"^(tap|brq)[a-f0-9]+\-[a-f0-9]+",  # cloudnet interfaces
    r"^vxlan-\d+",  # cloudnet vxlan interfaces
    r"^(br-internal|br-external|br-int)$",  # more cloudnet interfaces
    r"^\d+$",  # Netgear switch interfaces are just numbers.
    r"^lo([.:].+)",  # virtual interfaces
    r"^(public|private)$",  # ganeti interfaces
    r"^##PRIMARY##$",  # interface name placeholder
)

BLANK_CABLES_SITE_BLACKLIST = ('eqiad',)
CORE_SITES = ('eqiad', 'codfw')

interface_ct = ContentType.objects.get_for_model(Interface)


class Cables(Report):
    """Report on various cable-related errors."""

    description = __doc__

    def _port_names_test(self, queryset, regex, label):
        """Test and report each item in the query set (presumed to be a CableTermination) for its name matching the
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
                    self.log_failure(None,
                                     ("incorrectly named {} cable termination not assigned to any device"
                                      "(interface id: {}): {}")
                                     .format(label, cable.id, cable.name))
                else:
                    self.log_failure(cable.device,
                                     "incorrectly named {} cable termination: {}".format(label, cable.name))

        self.log_success(None, "{} correctly named {} cable terminations".format(successes, label))

    def test_console_port_termination_names(self):
        """Proxy to _port_names_test with values for checking console ports."""
        self._port_names_test(
            ConsolePort.objects.exclude(device__status__in=EXCLUDE_STATUSES),
            re.compile(r"console\d|console-re\d|serial\d"),
            "console port",
        )

    def test_console_server_port_termination_names(self):
        """Proxy to _port_names_test with values for checking console server ports."""
        self._port_names_test(
            ConsoleServerPort.objects.exclude(device__status__in=EXCLUDE_STATUSES),
            re.compile(r"port\d+"),
            "console server port",
        )

    def test_power_port_termination_names(self):
        """Proxy to _port_names_test with values for checking power ports."""
        self._port_names_test(
            PowerPort.objects.exclude(device__status__in=EXCLUDE_STATUSES),
            re.compile(r"PSU\d|PEM \d|Power Supply \d"),
            "power port",
        )

    def test_power_outlet_termination_names(self):
        """Proxy to _port_names_test with values for checking power outlets."""
        self._port_names_test(
            PowerOutlet.objects.exclude(device__status__in=EXCLUDE_STATUSES), re.compile(r"\d+"), "power outlet"
        )

    def test_interface_termination_names(self):
        """Proxy to _port_names_test with values for checking interfaces."""
        self._port_names_test(
            Interface.objects.exclude(device__status__in=EXCLUDE_STATUSES)
            .exclude(device__device_role__slug='server'),
            re.compile((r"|".join(INTERFACES_REGEXP))),
            "interface",
        )

    def _get_site_slug_for_cable(self, cable):
        """Get a representative site slug given a cable.

        Since cables do not have their own site objects, we need to get it from a subsidiary object, which,
        depending on the termination type, may be on the termination object or the device object in the termination.
        """
        site = "none"
        if cable.termination_a_type.name == "circuit termination" and cable.termination_a.site:
            site = cable.termination_a.site.slug
        elif cable.termination_a.device and cable.termination_a.device.site:
            site = cable.termination_a.device.site.slug
        return site

    def _core_site_server_cable(self, cable):
        """check if the cable is a core site server cable.

         Arguments:
            cable: Netbox cable
        Returns:
            true: the cable is a core site server cable.
            false: it's not.
        """
        if (cable.termination_a_type == interface_ct
                and cable.termination_a.device.device_role.slug == 'server'
                and cable.termination_a.device.site.slug in CORE_SITES):
            return True
        if (cable.termination_b_type == interface_ct
                and cable.termination_b.device.device_role.slug == 'server'
                and cable.termination_b.device.site.slug in CORE_SITES):
            return True
        return False

    def test_duplicate_cable_label(self):
        """Cables within sites should have unique labels."""
        labelcounts = defaultdict(list)
        for cable in (
            Cable.objects.exclude(label__isnull=True)
            .exclude(label='')
            .exclude(termination_a_id__isnull=True)
            .exclude(termination_b_id__isnull=True)
        ):
            if cable.label.strip():
                # Uniquify per site (duplicates between sites are ok, within sites not ok).
                site = self._get_site_slug_for_cable(cable)
                labelcounts[(cable.label.strip(), site)].append(cable)

        success = 0
        for label, cables in labelcounts.items():
            if len(cables) > 1:
                for cable in cables:
                    self.log_failure(cable, "duplicate cable label (site {})".format(label[1]))
            else:
                success += 1
        self.log_success(None, "{} non-duplicate cable labels".format(success))

    def test_blank_cable_label(self):
        """Cables should not have blank labels.

        Except for core sites servers (see T266533).
        """
        success = 0
        for cable in Cable.objects.filter(status=CableStatusChoices.STATUS_CONNECTED):
            if cable.label is None or not cable.label.strip():
                site = self._get_site_slug_for_cable(cable)
                if self._core_site_server_cable(cable):
                    continue
                if (cable.termination_a_type == interface_ct
                        and cable.termination_a.name.startswith('vcp-')):
                    self.log_warning(cable, "VC link with no cable ID (site {})".format(site))
                    continue
                if site in BLANK_CABLES_SITE_BLACKLIST:
                    self.log_warning(cable, "blank cable label (site {})".format(site))
                    continue
                self.log_failure(cable, "blank cable label (site {})".format(site))
            else:
                success += 1
        self.log_success(None, "{} non-blank cable labels".format(success))
