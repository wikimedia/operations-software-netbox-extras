"""Load a DNS resource record, and generate Netbox interfaces for each entry as appropriate."""

import argparse
import logging
import sys
from configparser import ConfigParser

import pynetbox

logger = logging.getLogger()

SITE_MGMT_MASKS = {"ulsfo": "/17", "eqsin": "/17", "codfw": "/16", "esams": "/24", "eqiad": "/16"}

SITE_MGMT_MASKS_FRACK = {"eqiad": "/26", "codfw": "/27"}


def setup_logging(verbose=False):
    """Setup the logging with a custom format to go to stdout."""
    if not verbose:
        level = logging.INFO
    else:
        level = logging.DEBUG

    logging.basicConfig(format="%(asctime)s [%(levelname)s] %(message)s", level=level)
    logging.StreamHandler()
    logging.getLogger("requests").setLevel(logging.WARNING)  # Silence noisy logger
    logger.raiseExceptions = False
    logger.setLevel(level)


def parse_args():
    """Setup command line argument parser and return parsed args.

    Returns:
        :obj:`argparse.Namespace`: The resulting parsed arguments.

    """
    parser = argparse.ArgumentParser()

    parser.add_argument("input", help="The path to read resource records from.")
    parser.add_argument(
        "-c",
        "--config",
        help="The path to the config file to load. Default: %(default)s.",
        default="/etc/netbox/scripts.cfg",
    )
    parser.add_argument("-v", "--verbose", help="Output more verbosity.", action="store_true")
    parser.add_argument("-d", "--dry_run", help="Only simulate import.", action="store_true")
    args = parser.parse_args()
    return args


def parse_rr(infile, record_types):
    """Parse a resource record, and return (host, origin, ip) tuples."""

    origin = ""
    records = []
    for line in infile:
        if line.startswith(";") or line.strip() == "":
            continue

        if line.startswith("$ORIGIN"):
            host = ""
            origin = line.split(None, 1)[1].split(";")[0].strip()[:-1]
            logger.debug("Origin switch: %s", origin)
        else:

            try:
                host, time, rnet, rtype, param = (x.strip() for x in line.split(None, 4))
            except ValueError:
                try:
                    # continuation from previous line (host falls through)
                    logger.debug("host fallthrough: %s", host)
                    time, rnet, rtype, param = (x.strip() for x in line.split(None, 3))
                except ValueError:
                    logger.warning("Line failed: %s, skipping.", line)
                    continue
            param = param.split(";")[0]
            logger.debug(line)
            if rtype not in record_types:
                logger.debug("Skipping out-of-type line (%s): %s.", rtype, line)
                continue

            records.append((host, origin, param))
    return records


def resolve_dns_with_netbox(api, host_dict, asset_dict, dry_run=False):
    """Resolve the management interface states in Netbox with the states represented by host_dict and asset_dict."""
    statuses = [
        x["value"]
        for x in api.dcim.choices()["device:status"]
        if x["label"] in ("Active", "Planned", "Staged", "Failed", "Inventory", "Decommissioning")
    ]
    hosts = api.dcim.devices.filter(role=["server", "pdu"], status=statuses)
    iface_type_1g = [x["value"] for x in api.dcim.choices()["interface:type"] if x["label"] == "1000BASE-T (1GE)"][0]
    iface_type_1m = [x["value"] for x in api.dcim.choices()["interface:type"] if x["label"] == "100BASE-TX (10/100ME)"][
        0
    ]
    frack_tenant_id = api.tenancy.tenants.get(slug="fr-tech").id
    for host in hosts:
        if host.name in host_dict:
            iface_rec = host_dict[host.name]
        elif host.custom_fields.get("asset_tag", None) in asset_dict:
            iface_rec = asset_dict[host.custom_fields["asset_tag"]]
        else:
            logger.warning("No information for host %s", host.name)
            continue

        iface_mask = SITE_MGMT_MASKS[host.site.slug]
        # special hack since frack has different netmasks
        ip_tenant = None
        if host.tenant and host.tenant.slug == "fr-tech":
            iface_mask = SITE_MGMT_MASKS_FRACK[host.site.slug]
            ip_tenant = frack_tenant_id
        iface_ip = iface_rec[2] + iface_mask
        iface_fqdn = "{}.{}".format(host.name, iface_rec[1])
        if host.device_role.slug == "pdu":
            mgmt_name = "net"
            mgmt_only = False
            if host.site.slug == 'esams':
                iface_type = iface_type_1g
            else:
                iface_type = iface_type_1m
        else:
            mgmt_name = "mgmt"
            mgmt_only = True
            iface_type = iface_type_1g

        interface = api.dcim.interfaces.get(name=mgmt_name, device_id=host.id)
        if interface:
            if not (interface.mgmt_only == mgmt_only):
                if dry_run:
                    logger.info("[DRY RUN] Would update interface mgmt_only for %s", host.name)
                else:
                    interface.mgmt_only = mgmt_only
                    logger.info("Updated mgmt interface mgmt_only for %s", host.name)
            if interface.type.value != iface_type:
                if dry_run:
                    logger.info("[DRY RUN] Would update interface type for %s", host.name)
                else:
                    interface.type = iface_type
                    logger.info("Updated interface type for %s", host.name)
            if not dry_run:
                interface.save()
        else:
            if dry_run:
                logger.info(
                    "[DRY RUN] would create management interface (%s) on %s (status: %s)",
                    mgmt_name,
                    host,
                    host.status.label,
                )
            else:
                interface = api.dcim.interfaces.create(device=host.id, name=mgmt_name, type=iface_type, mgmt_only=True)
                logger.info("Created management interface (%s) on %s (status: %s)", mgmt_name, host, host.status.label)

        ip = None
        try:
            if interface:
                ip = api.ipam.ip_addresses.get(interface_id=interface.id)
        except pynetbox.RequestError:
            ip = None
        if ip:
            if not iface_ip == ip.address:
                if dry_run:
                    logger.info(
                        "[DRY RUN] would update management interface %s ip address (was %s, would be %s).",
                        host.name,
                        ip.address,
                        iface_ip,
                    )
                else:
                    ip.address = iface_ip
                    logger.info(
                        "Updated management interface %s ip address (%s -> %s).", host.name, ip.address, iface_ip
                    )
            if not iface_fqdn == ip.dns_name:
                if dry_run:
                    logger.info(
                        "[DRY RUN] Would update management interface %s fqdn (was %s, would be %s) .",
                        host.name,
                        ip.dns_name,
                        iface_fqdn,
                    )
                else:
                    ip.dns_name = iface_fqdn
                    logger.info("Updated management interface %s fqdn (%s -> %s) .", host.name, ip.dns_name, iface_fqdn)
            if ip.tenant and not ip_tenant == ip.tenant.id:
                if dry_run:
                    logger.info("[DRY RUN] Would update management interface %s tenant.", host.name)
                else:
                    ip.tenant = ip_tenant
                    logger.info("Updated interface %s tenant.", host.name)
            if not dry_run:
                ip.save()
        else:
            if dry_run:
                logger.info("[DRY RUN] would create management ip %s for %s", iface_ip, host)
            else:
                api.ipam.ip_addresses.create(
                    address=iface_ip, dns_name=iface_fqdn, device=host.id, interface=interface.id, tenant=ip_tenant
                )
                logger.info("Created management ip %s for %s", iface_ip, host)

    return 0


def main():
    args = parse_args()
    setup_logging(args.verbose)

    # load configuration
    config = ConfigParser()
    config.read(args.config)
    netbox_token = config["netbox"]["token_rw"]
    netbox_api = config["netbox"]["api"]

    with open(args.input, "r") as inrecord:
        records = parse_rr(inrecord, ("AAAA", "A"))

    mgmt_by_host = {x[0]: x for x in records if x[1].startswith("mgmt") and not x[0].startswith("WMF")}
    mgmt_by_asset = {x[0]: x for x in records if x[1].startswith("mgmt") and x[0].startswith("WMF")}

    api = pynetbox.api(url=netbox_api, token=netbox_token)

    return resolve_dns_with_netbox(api, mgmt_by_host, mgmt_by_asset, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
