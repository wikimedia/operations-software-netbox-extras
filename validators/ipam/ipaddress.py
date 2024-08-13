import re

from extras.validators import CustomValidator

# TODO: query them or import them from wmflib
DATACENTERS = ("eqiad", "codfw", "esams", "ulsfo", "eqsin", "drmrs", "magru")


class Main(CustomValidator):
    """Main class referenced in the Netbox config"""

    def validate(self, instance, request):  # noqa: unused-argument
        """Mandatory entry point"""
        # dns_name
        if instance.dns_name:  # Accept empty values when there is no FQDN set
            if instance.dns_name.endswith("."):
                self.fail("Invalid DNS name: must not end with a dot", field="dns_name")

            if "." not in instance.dns_name:
                self.fail("Invalid DNS name: no dot found, it must be an FQDN, not a hostname", field="dns_name")

            parts = instance.dns_name.split(".")

            if getattr(instance.assigned_object, "mgmt_only", False):
                # Management IPs like host1001.mgmt.eqiad.wmnet and host1001.mgmt.frack.eqiad.wmnet
                if len(parts) < 4 or len(parts) > 5:
                    self.fail("Invalid DNS name: 4 or 5 domain levels are needed when assigned to a mgmt "
                              f"interface, got {len(parts)}", field="dns_name")
                if parts[-3] != "mgmt" and parts[-4] != "mgmt":
                    self.fail("Invalid DNS name: '.mgmt.' must be the third or forth subdomain when assigned to a "
                              f"mgmt interface, got {instance.dns_name}", field="dns_name")
                if parts[-1] != "wmnet":
                    self.fail("Invalid DNS name: it should end with '.wmnet' when assigned to a mgmt interface, "
                              f"got {parts[-1]}", field="dns_name")
                if parts[-2] not in DATACENTERS:
                    self.fail("Invalid DNS name: the second level domain should be a valid DC name when assigned "
                              f"to a mgmt interface, got {parts[-2]}", field="dns_name")
            else:
                # More strictly validate the FQDNs of IPs without role connected to the interface of a server and
                # being their primary IPs.
                device = getattr(instance.assigned_object, "device", None)
                if (device is not None and device.role.slug == "server" and not instance.role and (
                    (instance.family == 4 and device.primary_ip4 is instance)
                    or (instance.family == 6 and device.primary_ip6 is instance)
                )):
                    if parts[-1] not in ("wmnet", "org"):
                        self.fail(f"Invalid DNS name: TLDs should be .wmnet or .org for primary IPs, got {parts[-1]}",
                                  field="dns_name")
                    if parts[-1] == "wmnet" and parts[-2] not in DATACENTERS:
                        # TODO: check also that the VLAN is not a public one
                        self.fail("Invalid DNS name: if ending with .wmnet the second level domain should be a valid "
                                  f"DC name, got {parts[-2]}", field="dns_name")
                    if parts[-1] == "org" and parts[-2] != "wikimedia":
                        # TODO: check also that the VLAN is a public one
                        self.fail("Invalid DNS name: if ending with .org the second level domain should be wikimedia "
                                  f"got {parts[-2]}", field="dns_name")
                    if device.name not in instance.dns_name:  # Allow also for cassandra special naming
                        self.fail("Invalid DNS name: if is a primary FQDN it should have the device name as part of "
                                  f"the FQDN, {device.name} not in {instance.dns_name}", field="dns_name")

            allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
            if not all(allowed.match(x) for x in instance.dns_name.split(".")):
                self.fail("Invalid DNS name: must be a valid FQDN", field="dns_name")
