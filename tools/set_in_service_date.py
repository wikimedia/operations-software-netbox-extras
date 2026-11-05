#!/usr/bin/python3
#
# Sets the Netbox In Service Date for physical servers, which is used by
# accounting for the depreciation of assets.
#
# 1. Queries Netbox for hosts that were purchased after the accounting start
#    date and whose in service date is unset.
# 2. Queries Puppet for hosts which have a production role role, i.e. not an
#    insetup role.
# 3. Takes the set intersection of those hosts and updates their In Service
#    Date to today.
#
import argparse
import datetime as dt
import logging
import re
import sys
from configparser import ConfigParser
from pathlib import Path

import pynetbox
import requests
from wmflib.requests import http_session as wmflib_http_session

log = logging.getLogger()


def parse_command_line_args() -> argparse.Namespace:
    """Parse command line options."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-c",
        "--config",
        default="/etc/netbox/update-in-service-date.ini",
        help="The path to the config file to load.",
    )
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        help="Don't actually commit any changes, just do a dry-run",
    )
    parser.add_argument(
        "-v", "--verbose", help="Increase verbosity.", action="store_true"
    )
    parser.add_argument(
        "-r",
        "--regex",
        default=".*",
        help="Host name regex filter",
    )
    parser.add_argument(
        "-u",
        "--unset",
        action="store_true",
        help="Unset in service date",
    )
    return parser.parse_args()


def puppet_hosts_in_service(puppetdb_url, host_regex):
    inventory_url = puppetdb_url + "/pdb/query/v4/inventory"
    # Find physical hosts that are not in an insetup role and match our regex
    insrv_query = {
        "query": [
            "extract",
            ["certname"],
            [
                "and",
                ["~", "facts.networking.fqdn", host_regex],
                ["=", "facts.is_virtual", False],
                [
                    "not",
                    [
                        "subquery",
                        "resources",
                        [
                            "and",
                            ["=", "type", "Class"],
                            ["~", "title", "Role::Insetup::.*"],
                        ],
                    ],
                ],
            ],
            ["group_by", "certname"],
        ]
    }

    resp = requests.post(inventory_url, json=insrv_query, timeout=(3, 60))
    if resp.status_code != 200:
        resp.raise_for_status()
    hosts = set()
    for puppet_host in resp.json():
        hosts.add(puppet_host["certname"].split(".")[0])
    return hosts


def setup_logging(verbose: bool = False, dry_run: bool = False) -> None:
    """Setup the logging with a custom format to go to stdout."""
    level = logging.DEBUG if verbose else logging.INFO
    prefix = " [DRY-RUN]" if dry_run else ""
    logging.basicConfig(format=f"[%(levelname)s]{prefix} %(message)s", level=level)


def unset_netbox_in_service_date(devices, dry_run) -> int:
    unset_devices = []
    for device in devices:
        if device.custom_fields["in_service_date"] is not None:
            device.custom_fields["in_service_date"] = None
            unset_devices.append(device)
    if not dry_run and len(unset_devices) > 0:
        unset_confirm = input(
            f"Unset in service date on {len(unset_devices)} devices? (y/n): "
        )
        if unset_confirm.lower() not in ["y"]:
            return 1
        for device in unset_devices:
            log.info("Netbox device %s - unset in service date", device.name)
            device.save()
    return 0


def netbox_devices(nb, start_date, regex):
    # TODO: Revisit this query when we are on Netbox v4.3 or higher, we could
    # probably do a much more performant GraphQL query, we could filter on
    # purchase_date and is null:
    # - https://github.com/netbox-community/netbox/issues/7598
    # - https://github.com/netbox-community/netbox/issues/8821
    nb_devices = nb.dcim.devices.filter(
        status=["active", "failed"],
        role="server",
        cf_purchase_date__gte=start_date.isoformat(),
    )
    filtered_nb_devices = []
    for nb_device in nb_devices:
        if re.search(regex, nb_device.name):
            filtered_nb_devices.append(nb_device)
    return filtered_nb_devices


def main() -> int:
    args = parse_command_line_args()
    setup_logging(args.verbose, args.dry_run)
    cfg = ConfigParser()
    with open(args.config, encoding="utf-8") as cfg_file:
        cfg.read_file(cfg_file)

    nb = pynetbox.api(cfg["netbox"]["url"], cfg["netbox"]["token"])
    session = wmflib_http_session(Path(__file__).name, timeout=(3, 60))
    nb.http_session = session

    start_date = dt.date.fromisoformat(cfg["general"]["start_date"])
    nb_devices = netbox_devices(nb, start_date, args.regex)

    if args.unset:
        return unset_netbox_in_service_date(nb_devices, args.dry_run)

    nb_devices_insrv_date_unset = {}
    for nb_device in nb_devices:
        if nb_device.custom_fields["in_service_date"] is None:
            nb_devices_insrv_date_unset[nb_device.name] = nb_device

    if len(nb_devices_insrv_date_unset) == 0:
        log.info("Netbox no hosts with their in service date unset")
        return 0

    log.info(
        "Netbox hosts with their in service date unset: %s",
        len(nb_devices_insrv_date_unset),
    )

    pp_hosts_insrv = puppet_hosts_in_service(cfg["puppetdb"]["url"], args.regex)
    log.info("Puppet hosts in service: %s", len(pp_hosts_insrv))

    nb_hosts_insrv_ready = set(nb_devices_insrv_date_unset) & pp_hosts_insrv
    log.info(
        "Netbox hosts in service date ready to be set: %s",
        len(nb_hosts_insrv_ready),
    )

    today = dt.date.today()
    for nb_host_insrv_ready in nb_hosts_insrv_ready:
        nb_device = nb_devices_insrv_date_unset[nb_host_insrv_ready]
        nb_device.custom_fields["in_service_date"] = today.isoformat()
        log.info(
            "Netbox device %s - purchase date: %s, set in service date: %s",
            nb_device.name,
            nb_device.custom_fields["purchase_date"],
            nb_device.custom_fields["in_service_date"],
        )
        if not args.dry_run:
            nb_device.save()
    return 0


if __name__ == "__main__":
    sys.exit(main())
