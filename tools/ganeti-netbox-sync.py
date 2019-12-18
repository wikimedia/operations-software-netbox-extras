#!/usr/bin/env python3
"""
ganeti-netbox-sync

This script synchronizes ganeti Instance state with Netbox virtualization.virtual_hosts state, and
assigns Netbox devices which match Ganeti nodes to Netbox's dcim.device.cluster.
"""

import argparse
import json
import logging
import sys

from collections import Counter
from configparser import ConfigParser

import pynetbox.api
import requests
from requests.auth import HTTPBasicAuth

logger = logging.getLogger()


def parse_command_line_args():
    """Parse command line options."""
    parser = argparse.ArgumentParser()

    parser.add_argument("profile", help="The profile to use from the configuration file.")
    parser.add_argument(
        "-i",
        "--instances-json",
        help=(
            "the path of a JSON file with the output of the Ganeti RAPI `instances&bulk=1` endpoint to process "
            "instead of accessing the API directly."
        ),
    )
    parser.add_argument(
        "-n",
        "--nodes-json",
        help=(
            "the path of a JSON file with the output of the Ganeti RAPI `nodes` endpoint to process instead of "
            "accessing the API directly."
        ),
    )
    parser.add_argument(
        "-c", "--config", help="The path to the config file to load.", default="/etc/netbox/ganeti-sync.cfg"
    )
    parser.add_argument(
        "-d", "--dry-run", help="Don't actually commit any changes, just do a dry-run", action="store_true"
    )
    parser.add_argument("-v", "--verbose", help="Output more verbosity.", action="store_true")

    args = parser.parse_args()

    # validation and manipulation
    if args.dry_run:
        args.verbose = True

    return args


def setup_logging(verbose=False):
    """Setup the logging with a custom format to go to stdout."""
    formatter = logging.Formatter(fmt="%(asctime)s [%(levelname)s] %(message)s")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    if not verbose:
        level = logging.INFO
    else:
        level = logging.DEBUG
    handler.setLevel(level)
    logging.getLogger("requests").setLevel(logging.WARNING)  # Silence noisy logger
    logger.addHandler(handler)
    logger.raiseExceptions = False
    logger.setLevel(level)


def ganeti_rapi_query(endpoint, base_url, user, password, ca_cert):
    """Execute the GET verb on a specified Ganeti endpoint."""
    target_url = "/".join((base_url.strip("/"), "2", endpoint))
    r = requests.get(target_url, auth=HTTPBasicAuth(user, password), verify=ca_cert, timeout=30)
    if r.status_code != 200:
        raise Exception("Can't access Ganeti API %s %s".format(r.status_code, r.text))
    return r.json()


def ganeti_host_to_netbox(ganeti_dict, virtual_machine_statuses, additional_fields):
    """Takes a single entry from the Ganeti host list and returns just the fields pertinent to Netbox
    along with any additional fields that need to be added"""
    shortname = ganeti_dict["name"].split(".")[0]
    output = {
        "name": shortname,
        "vcpus": ganeti_dict["beparams"]["vcpus"],
        "memory": ganeti_dict["beparams"]["memory"],
        "disk": round(sum(ganeti_dict["disk.sizes"]) / 1024, 0),  # ganeti gives megabytes, netbox expects gigabytes
    }
    # admin_state is the desired state of the machine, which maps nicely to the status field.
    if ganeti_dict["admin_state"] == "up":
        output["status"] = virtual_machine_statuses["Active"]
    else:
        output["status"] = virtual_machine_statuses["Offline"]
    output.update(additional_fields)
    return output


def sync_ganeti_netbox_host_diff(ganeti_host, netbox_host):
    """Update fields on netbox_host from ganeti_dict, return True if updates are made."""
    updated = False
    if netbox_host.vcpus != ganeti_host["vcpus"]:
        logger.debug("updating vcpus on %s %d -> %d", netbox_host.name, netbox_host.vcpus, ganeti_host["vcpus"])
        netbox_host.vcpus = ganeti_host["vcpus"]
        updated = True
    if netbox_host.memory != ganeti_host["memory"]:
        logger.debug("updating memory on %s %d -> %d", netbox_host.name, netbox_host.memory, ganeti_host["memory"])
        netbox_host.memory = ganeti_host["memory"]
        updated = True
    if netbox_host.disk != ganeti_host["disk"]:
        logger.debug("updating disk on %s %d -> %d", netbox_host.name, netbox_host.disk, ganeti_host["disk"])
        netbox_host.disk = ganeti_host["disk"]
        updated = True
    if netbox_host.status.value != ganeti_host["status"]:
        logger.debug(
            "updating status on %s %d -> %d", netbox_host.name, netbox_host.status.value, ganeti_host["status"]
        )
        netbox_host.status = ganeti_host["status"]
        updated = True

    return updated


def sync_ganeti_to_netbox(netbox_api, netbox_token, cluster_name, ganeti_hosts, dryrun):
    """Preform a sync from the Ganeti host list into the specified Netbox API destination."""
    nbapi = pynetbox.api(netbox_api, token=netbox_token)

    nb_linux_id = nbapi.dcim.platforms.get(slug="linux").id
    nb_cluster_id = nbapi.virtualization.clusters.get(name=cluster_name).id
    nb_server_id = nbapi.dcim.device_roles.get(slug="server").id

    nb_vhost_statuses = {ch["label"]: ch["value"] for ch in nbapi.virtualization.choices()["virtual-machine:status"]}

    nb_vhosts = {}
    # make a convenient dictionary of netbox hosts
    for host in nbapi.virtualization.virtual_machines.filter(cluster=nb_cluster_id):
        nb_vhosts[host.name] = host

    results = Counter()
    for nb_host_name, nb_host in nb_vhosts.items():
        if nb_host_name not in ganeti_hosts:
            if not dryrun:
                nb_host.delete()
            logger.debug("removed %s from netbox", nb_host_name)
            results["del"] += 1
        else:
            try:
                ganeti_host = ganeti_host_to_netbox(ganeti_hosts[nb_host_name], nb_vhost_statuses, {})
            except (KeyError, TypeError) as e:
                logger.error(
                    "Host %s raised an exception when trying to convert to Netbox for syncing: %s", nb_host_name, e
                )
                continue

            try:
                diff_result = sync_ganeti_netbox_host_diff(ganeti_host, nb_host)
            except KeyError as e:
                logger.error("Host %s raised an exception when trying to resolve diff: %s", nb_host_name, e)
                continue
            if diff_result:
                logger.debug("updating %s in netbox", nb_host_name)
                if not dryrun:
                    nb_host.save()
                results["update"] += 1

    logger.info("removed %s instances from netbox", results["del"])
    logger.info("updated %s instances from netbox", results["update"])

    for ganeti_host_name, ganeti_host in ganeti_hosts.items():
        if ganeti_host_name in nb_vhosts:
            continue

        try:
            ganeti_host_dict = ganeti_host_to_netbox(
                ganeti_host,
                nb_vhost_statuses,
                {"cluster": nb_cluster_id, "platform": nb_linux_id, "role": nb_server_id},
            )
        except (KeyError, TypeError) as e:
            logger.error(
                "Host %s raised an exception when trying to convert to Netbox for adding: %s", ganeti_host_name, e
            )
            continue
        if dryrun:
            save_result = True
        else:
            try:
                save_result = nbapi.virtualization.virtual_machines.create(ganeti_host_dict)
            except pynetbox.RequestError as e:
                logger.error("Host %s raised an exception when trying to create in Netbox: %s", ganeti_host_name, e)
                continue

        if save_result:
            results["add"] += 1
            logger.debug("adding %s to netbox", ganeti_host_dict["name"])
        else:
            logger.error("error added %s to netbox", ganeti_host_dict["name"])
    logger.info("added %s instances to netbox", results["add"])


def sync_ganeti_nodes_to_netbox(netbox_api, netbox_token, cluster_name, ganeti_nodes, dry_run):
    """Perform a sync between the Ganeti Node list and the Netbox API"""
    nbapi = pynetbox.api(netbox_api, token=netbox_token)
    nb_cluster_id = nbapi.virtualization.clusters.get(name=cluster_name).id

    nb_cluster_nodes = {n.name: n for n in nbapi.dcim.devices.filter(cluster_id=nb_cluster_id)}
    results = Counter()
    for node in ganeti_nodes:
        if node not in nb_cluster_nodes.keys():
            try:
                device = nbapi.dcim.devices.get(name=node)
            except pynetbox.RequestError as e:
                logger.error("an error was raised trying to retrieve host %s: %s", node, e)
                continue

            if device is not None:
                device.cluster = nb_cluster_id
                if dry_run:
                    save_result = True
                else:
                    try:
                        save_result = device.save()
                    except pynetbox.RequestError as e:
                        logger.error("an error was raised trying to save host %s: %s", node, e)
                        continue

                if save_result:
                    results["assign"] += 1
                    logger.debug("assigned %s to %s", node, cluster_name)
                else:
                    logger.error("error assigning %s to %s", node, cluster_name)
            else:
                logger.error("device %s does not exist in netbox to assign to cluster %s", node, cluster_name)

    logger.info("assigned %d hosts to cluster %s", results["assign"], cluster_name)

    removals = set(nb_cluster_nodes.keys()) - set(ganeti_nodes)
    for node in removals:
        device = nb_cluster_nodes[node]
        device.cluster_id = None
        if dry_run:
            save_result = True
        else:
            try:
                save_result = device.save()
            except pynetbox.RequestError as e:
                logger.error("an error was raised trying to save host %s: %s", node, e)
                continue
        if save_result:
            results["remove"] += 1
            logger.debug("removed %s from %s", node, cluster_name)
        else:
            logger.error("error removing %s from %s", node, cluster_name)

    logger.info("removed %d hosts from cluster %s", results["remove"], cluster_name)


def main():
    """Entry point for Ganeti->Netbox Sync."""
    args = parse_command_line_args()
    # Load configuration
    cfg = ConfigParser()
    cfg.read(args.config)
    logger.info("loaded %s configuration", args.config)
    netbox_token = cfg["auth"]["netbox_token"]
    ganeti_user = cfg["auth"]["ganeti_user"]
    ganeti_password = cfg["auth"]["ganeti_password"]
    netbox_api = cfg["netbox"]["api"]
    netbox_cluster = cfg["profile:" + args.profile]["cluster"]
    ganeti_api = cfg["profile:" + args.profile]["api"]
    ganeti_ca_cert = cfg["auth"]["ca_cert"]

    setup_logging(args.verbose)

    logger.debug("using ganeti api at %s", ganeti_api)
    logger.debug("using netbox api at %s", netbox_api)

    if args.dry_run:
        logger.info("*** DRY RUN ***")

    # Sync Hosts
    if args.instances_json:
        logger.info("note: loading json file rather than accessing ganeti api %s", args.instances_json)
        with open(args.instances_json, "r") as in_json:
            ganeti_hosts_json = json.load(in_json)
    else:
        ganeti_hosts_json = ganeti_rapi_query(
            "instances?bulk=1", ganeti_api, ganeti_user, ganeti_password, ganeti_ca_cert
        )

    # Convert instances JSON to a dict keyed by the host name
    ganeti_hosts = {i["name"].split(".")[0]: i for i in ganeti_hosts_json}
    logger.debug("loaded %d instances from ganeti api", len(ganeti_hosts))
    sync_ganeti_to_netbox(netbox_api, netbox_token, netbox_cluster, ganeti_hosts, args.dry_run)

    # Sync Nodes
    if args.nodes_json:
        logger.info("note: loading json file rather than accessing ganeti api %s", args.nodes_json)
        with open(args.nodes_json, "r") as in_json:
            ganeti_nodes_json = json.load(in_json)
    else:
        ganeti_nodes_json = ganeti_rapi_query("nodes", ganeti_api, ganeti_user, ganeti_password, ganeti_ca_cert)

    # Convert nodes JSON to a list of nodes that run this cluster
    ganeti_nodes = [x["id"].split(".", 1)[0] for x in ganeti_nodes_json]
    logger.debug("loaded %d nodes from ganeti api", len(ganeti_nodes))
    sync_ganeti_nodes_to_netbox(netbox_api, netbox_token, netbox_cluster, ganeti_nodes, args.dry_run)

    return 0


if __name__ == "__main__":
    sys.exit(main())
