"""Load a DNS resource record, and generate Netbox interfaces for each entry as appropriate."""

import argparse
import logging
import sys
from configparser import ConfigParser

import pynetbox

logger = logging.getLogger()

SITE_MGMT_MASKS = {'ulsfo': '/17', 'eqsin': '/17', 'codfw': '/16', 'esams': '/24', 'eqiad': '/16'}

SITE_MGMT_MASKS_FRACK = {'eqiad': '/26', 'codfw': '/24'}


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
    args = parser.parse_args()
    return args


def parse_rr(infile, record_types):
    """Parse a resource record, and return (host, origin, ip) tuples."""

    origin = ''
    records = []
    for line in infile:
        if line.startswith(';'):
            continue

        if line.startswith('$ORIGIN'):
            host = ''
            origin = line.split(None, 1)[1].split(';')[0].strip()[:-1]
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
            param = param.split(';')[0]
            logger.debug(line)
            if rtype not in record_types:
                logger.debug("Skipping out-of-type line (%s): %s.", rtype, line)
                continue

            records.append((host, origin, param))
    return records


def resolve_dns_with_netbox(api, host_dict, asset_dict):
    """Resolve the management interface states in Netbox with the states represented by host_dict and asset_dict."""
    statuses = [
        x['value'] for x in api.dcim.choices()['device:status'] if x['label'] in ('Active', 'Planned', 'Staged')
    ]
    hosts = api.dcim.devices.filter(role='server', status=statuses)
    iface_type = [x['value'] for x in api.dcim.choices()['interface:type'] if x['label'] == '1000BASE-T (1GE)'][0]
    frack_tenant_id = api.tenancy.tenants.get(slug='fr-tech').id
    for host in hosts:
        if host.name in host_dict:
            iface_rec = host_dict[host.name]
        elif host.custom_fields.get('asset_tag', None) in asset_dict:
            iface_rec = asset_dict[host.custom_fields['asset_tag']]
        else:
            logger.warning('No information for host %s', host.name)
            continue

        iface_mask = SITE_MGMT_MASKS[host.site.slug]
        # special hack since frack has different netmasks
        ip_tenant = None
        if host.tenant and host.tenant.slug == 'fr-tech':
            iface_mask = SITE_MGMT_MASKS_FRACK[host.site.slug]
            ip_tenant = frack_tenant_id
        iface_ip = iface_rec[2] + iface_mask
        iface_fqdn = '{}.{}'.format(host.name, iface_rec[1])
        interface = api.dcim.interfaces.get(name='mgmt', device_id=host.id)
        if interface:
            if not interface.mgmt_only:
                interface.mgmt_only = True
                logger.info('Updated mgmt interface mgmt_only for %s', host.name)
            if interface.type.value != iface_type:
                interface.type = iface_type
                logger.info('Updated mgmt interface type for %s', host.name)

            interface.save()
        else:
            interface = api.dcim.interfaces.create(device=host.id, name='mgmt', type=iface_type, mgmt_only=True)
            logger.info("Created mgmt interface for %s", host.name)

        ip = api.ipam.ip_addresses.get(interface_id=interface.id)
        if ip:
            if not iface_ip == ip.address:
                ip.address = iface_ip
                logger.info('Updated mgmt interface %s ip address.', host.name)
            if not iface_fqdn == ip.dns_name:
                ip.dns_name = iface_fqdn
                logger.info('Updated mgmt interface %s fqdn.', host.name)
            if ip.tenant and not ip_tenant == ip.tenant.id:
                ip.tenant = ip_tenant
                logger.info('Updated mgmt interface %s tenant.', host.name)
            ip.save()
        else:
            api.ipam.ip_addresses.create(
                address=iface_ip, dns_name=iface_fqdn, device=host.id, interface=interface.id, tenant=ip_tenant
            )
            logger.info('Created mgmt ip address for %s', host.name)

    return 0


def main():
    args = parse_args()
    setup_logging(args.verbose)

    # load configuration
    config = ConfigParser()
    config.read(args.config)
    netbox_token = config["netbox"]["token_rw"]
    netbox_api = config["netbox"]["api"]

    with open(args.input, 'r') as inrecord:
        records = parse_rr(inrecord, ('AAAA', 'A'))

    mgmt_by_host = {x[0]: x for x in records if x[1].startswith('mgmt') and not x[0].startswith('WMF')}
    mgmt_by_asset = {x[0]: x for x in records if x[1].startswith('mgmt') and x[0].startswith('WMF')}

    api = pynetbox.api(url=netbox_api, token=netbox_token)

    return resolve_dns_with_netbox(api, mgmt_by_host, mgmt_by_asset)


if __name__ == "__main__":
    sys.exit(main())
