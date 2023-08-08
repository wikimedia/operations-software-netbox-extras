#!/usr/bin/env python3
"""Synchronize Ganeti data to Netbox."""
import argparse
import logging

from collections import Counter
from configparser import ConfigParser
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Callable, Counter as CounterType, Dict, Optional, Tuple

import pynetbox
import requests

from wmflib.requests import http_session as wmflib_http_session

logger = logging.getLogger()


def parse_command_line_args() -> argparse.Namespace:
    """Parse command line options."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", help="The profile to use from the configuration file.")
    parser.add_argument(
        "-c", "--config", default="/etc/netbox/ganeti-sync.cfg", help="The path to the config file to load."
    )
    parser.add_argument(
        "-d", "--dry-run", action="store_true", help="Don't actually commit any changes, just do a dry-run"
    )
    parser.add_argument("-v", "--verbose", help="Output more verbosity.", action="store_true")

    args = parser.parse_args()

    if args.dry_run:
        args.verbose = True

    return args


def setup_logging(verbose: bool = False, dry_run: bool = False) -> None:
    """Setup the logging with a custom format to go to stdout."""
    level = logging.DEBUG if verbose else logging.INFO
    requests_level = logging.INFO if verbose else logging.WARNING
    prefix = "DRY-RUN " if dry_run else ""
    logging.basicConfig(format=f"%(asctime)s [%(levelname)s] {prefix}%(message)s", level=level)
    logging.getLogger("requests").setLevel(requests_level)  # Silence noisy logger


@dataclass
class Ganeti:
    """Class to fetch data from the Ganeti API to populate Netbox."""

    url: str
    port: str
    username: str
    password: str
    http_session: requests.sessions.Session

    def _query(self, endpoint: str) -> Dict:
        """GET the provided endpoint from the Ganeti API."""
        response = self.http_session.get(
            f"https://{self.url}:{self.port}/2/{endpoint}",
            auth=requests.auth.HTTPBasicAuth(self.username, self.password),
        )

        if response.status_code != requests.codes.ok:
            raise RuntimeError(f"Ganeti API call to {endpoint} failed with {response.status_code}:\n{response.text}")

        return response.json()

    def get_instances(self) -> Dict[str, Dict]:
        """Return the instances of the current cluster."""
        instances = {}
        for instance in self._query("instances?bulk=1"):
            try:
                name = instance["name"].split(".", 1)[0]
                instances[name] = {
                    "name": name,
                    "vcpus": instance["beparams"]["vcpus"],
                    "memory": instance["beparams"]["memory"],
                    "disk": round(sum(instance["disk.sizes"]) / 1024, 0),  # Ganeti returns MB, Netbox expects GB
                    "status": "active" if instance["admin_state"] == "up" else "offline",
                    "primary_node": instance["pnode"].split(".")[0],
                }
            except (KeyError, TypeError) as e:
                logger.error("Failed to get data for Ganeti instance %s: %s", name, e)
                continue

        logger.debug("Loaded %d Ganeti instances in cluster %s", len(instances), self.url)
        return instances

    def get_groups(self) -> Dict:
        """Return the groups and members of the current cluster."""
        groups = {}
        for group in self._query("groups?bulk=1"):
            groups[group["name"]] = [node.split(".")[0] for node in group["node_list"]]
            logger.debug(
                "Loaded %d Ganeti nodes for group %s in cluster %s", len(group["node_list"]), group["name"], self.url
            )

        return groups


@dataclass
class Netbox:
    """Base Netbox class with common functionalities."""

    api: pynetbox.api
    dry_run: bool

    def __post_init__(self) -> None:
        """Initialize additional instance variables."""
        self.server_id = self.api.dcim.device_roles.get(slug="server").id

    def _create_resource(self, resource: str, func: Callable, data: Dict) -> Optional[pynetbox.core.response.Record]:
        """Create a resource, dry-run aware. Returns the created object or None on failure."""
        name = data["name"]
        logger.info("Creating %s %s with data: %s", resource, name, data)
        if self.dry_run:
            logger.info("Skip resource creation in DRY-RUN mode. The script will fail early.")
            return None

        try:
            created = func(data)
        except pynetbox.RequestError as e:
            logger.error("Failed to create %s %s in Netbox: %s", resource, name, e)
            created = None

        return created


@dataclass
class NetboxClusterGroup(Netbox):
    """Class to manage Netbox cluster groups and all their members."""

    cluster_group_name: str
    site: str

    def __post_init__(self) -> None:
        """Initialize additional instance variables."""
        super().__post_init__()
        self.cluster_group = self.api.virtualization.cluster_groups.get(name=self.cluster_group_name)
        if self.cluster_group is None:
            raise RuntimeError(
                f"Cluster group {self.cluster_group_name} does not exist. "
                "It must be created on Netbox before running this script."
            )
        self.cluster_type_id = self.api.virtualization.cluster_types.get(name="Ganeti").id
        self.site_id = self.api.dcim.sites.get(slug=self.site).id

    def get_clusters(self) -> Dict:
        """Return all clusters of the current cluster group."""
        clusters = {}
        for cluster in self.api.virtualization.clusters.filter(group_id=self.cluster_group.id):
            clusters[cluster.name] = NetboxCluster(api=self.api, cluster=cluster, dry_run=self.dry_run)
        logger.debug("Loaded %d Netbox clusters in cluster group %s", len(clusters), self.cluster_group_name)
        return clusters

    def ensure_cluster(self, data: Dict) -> Tuple[str, Optional["NetboxCluster"]]:
        """Create or move a Cluster with the given data and return it, along with the operation performed."""
        # name and site must be unique in Netbox
        cluster = self.api.virtualization.clusters.get(name=data["name"], site_id=self.site_id)
        if cluster:
            operation = "updated"
            cluster.type = self.cluster_type_id
            cluster.group = self.cluster_group.id
            cluster.save()
        else:
            operation = "created"
            data.update({"type": self.cluster_type_id, "site": self.site_id, "group": self.cluster_group.id})
            cluster = self._create_resource("Cluster", self.api.virtualization.clusters.create, data)
            if not cluster:
                raise RuntimeError(
                    f'Failed to create cluster {data["name"]} in cluster group {self.cluster_group_name}'
                )

        return operation, NetboxCluster(api=self.api, cluster=cluster, dry_run=self.dry_run) if cluster else cluster


@dataclass
class NetboxCluster(Netbox):

    cluster: pynetbox.core.response.Record

    def _set_device_cluster(self, device_name: str, *, unset: bool = False) -> bool:
        """Update a device setting the cluster ID or unset it."""
        try:
            device = self.api.dcim.devices.get(name=device_name)
        except pynetbox.RequestError as e:
            logger.error("Unable to load device %s on Netbox: %s", device, e)
            return False

        cluster_id = None if unset else self.cluster.id
        logger.info("Setting cluster ID to %s for device %s", cluster_id, device)
        if self.dry_run:
            return True

        try:
            device.cluster = cluster_id
            device.save()
            return True
        except pynetbox.RequestError as e:
            logger.error("Failed to save Netbox device %s: %s", device, e)
            return False

    def puppetdb_import(self) -> None:
        """Execute PuppetDB import on any host that have the placeholder PRIMARY interface."""
        reimport = [
            str(iface.virtual_machine)
            for iface in self.api.virtualization.interfaces.filter(name="##PRIMARY##", cluster_id=self.cluster.id)
        ]
        if not reimport:
            return

        logger.info("Running PuppetDB import script for %d VMs.", len(reimport))
        url = f"{self.api.base_url}/extras/scripts/interface_automation.ImportPuppetDB/"
        headers = {"Authorization": f"Token {self.api.token}"}
        data = {"data": {"device": " ".join(reimport)}, "commit": not self.dry_run}
        result = self.api.http_session.post(url, headers=headers, json=data)
        if result.status_code == 200:
            logger.debug("Executed import, result: %s", result.text)
        else:
            logger.error("Error executing PuppetDB import: %s", result.text)

    def get_vms(self) -> Dict:
        """Return all the VMs for the current cluster."""
        vms = {vm.name: vm for vm in self.api.virtualization.virtual_machines.filter(cluster_id=self.cluster.id)}
        logger.debug("Loaded %d Netbox VMs in cluster %s", len(vms), self.cluster)
        return vms

    def get_devices(self) -> Dict:
        """Return all the physical devices that are part of the current cluster."""
        devices = {device.name: device for device in self.api.dcim.devices.filter(cluster_id=self.cluster.id)}
        logger.debug("Loaded %d Netbox devices in cluster %s (ID %d)", len(devices), self.cluster, self.cluster.id)
        return devices

    def create_vm(self, orig_data: Dict) -> Optional[pynetbox.core.response.Record]:
        """Create a VM with the given data and return a boolean that tells if it was created successfully."""
        existing = self.api.virtualization.virtual_machines.get(name=orig_data["name"])
        if existing is not None:
            existing.cluster = self.cluster.id
            existing.save()
            return existing

        data = {key: value for key, value in orig_data.items() if key != "primary_node"}
        data.update({"cluster": self.cluster.id, "role": self.server_id})
        vm = self._create_resource("VM", self.api.virtualization.virtual_machines.create, data)
        if not vm:
            raise RuntimeError(f'Failed to create VM {orig_data["name"]} in cluster {self.cluster}')
        return vm

    def add_device(self, device: str) -> bool:
        """Add a physical device to the current cluster."""
        return self._set_device_cluster(device)

    def remove_device(self, device: str) -> bool:
        """Remove a physical device from the current cluster."""
        return self._set_device_cluster(device, unset=True)


@dataclass
class GanetiNetboxSyncer:
    """Class to perform the sync from Ganeti to Netbox."""

    netbox: NetboxClusterGroup
    ganeti: Ganeti
    dry_run: bool
    actions: CounterType = dataclass_field(default_factory=Counter)
    netbox_clusters: Dict = dataclass_field(default_factory=dict)
    ganeti_groups: Dict = dataclass_field(default_factory=dict)

    def sync(self) -> None:
        """Start the recursive sync of all resources."""
        self.netbox_clusters = self.netbox.get_clusters()
        self.ganeti_groups = self.ganeti.get_groups()
        self.add_clusters()
        self.sync_nodes()
        self.sync_vms()
        self.remove_clusters()

    def add_clusters(self) -> None:
        """Add Ganeti groups as Netbox clusters as member of the current cluster group."""
        for group, nodes in self.ganeti_groups.items():
            if group in self.netbox_clusters:
                continue

            operation, cluster = self.netbox.ensure_cluster({"name": group})
            if cluster:
                self.netbox_clusters[group] = cluster

            self.actions[f"Clusters {operation}"] += 1

    def remove_clusters(self) -> None:
        """Remove clusters in the current cluster group if not present in Ganeti."""
        to_remove = []
        for name, cluster in self.netbox_clusters.items():
            if name in self.ganeti_groups:
                continue

            logger.info("Deleting Cluster %s from netbox", name)
            if not self.dry_run and cluster:
                cluster.cluster.delete()

            to_remove.append(name)
            self.actions["Clusters deleted"] += 1

        for name in to_remove:
            del self.netbox_clusters[name]

    def sync_nodes(self) -> None:
        """Sync Ganeti nodes for each group to Netbox cluster members."""
        for group, ganeti_nodes in self.ganeti_groups.items():
            netbox_cluster = self.netbox_clusters[group]
            netbox_devices = netbox_cluster.get_devices()
            for node in ganeti_nodes:
                if node in netbox_devices:
                    continue

                created = netbox_cluster.add_device(node)
                if created:
                    self.actions["Nodes added"] += 1
                else:
                    self.actions["Nodes failed"] += 1

            for name, device in netbox_devices.items():
                if name in ganeti_nodes:
                    continue

                deleted = netbox_cluster.remove_device(name)
                if deleted:
                    self.actions["Nodes removed"] += 1
                else:
                    self.actions["Nodes failed"] += 1

    def sync_vms(self) -> None:
        """Sync Ganeti VMs to Netbox for all cluster in the cluster group."""
        ganeti_instances = self.ganeti.get_instances()
        for name, cluster in self.netbox_clusters.items():
            logger.info("Syncing VMs for cluster %s", name)
            if name in self.ganeti_groups:
                instances = {
                    key: value
                    for key, value in ganeti_instances.items()
                    if value["primary_node"] in self.ganeti_groups[name]
                }
            else:
                instances = {}

            self.sync_cluster_vms(cluster, instances)
            cluster.puppetdb_import()

    def sync_cluster_vms(self, cluster: pynetbox.core.response.Record, ganeti_instances: Dict[str, Dict]) -> None:
        """Sync Ganeti VMs to Netbox for the given cluster."""
        netbox_vms = cluster.get_vms()
        for netbox_vm_hostname, netbox_vm in netbox_vms.items():
            if netbox_vm_hostname not in ganeti_instances:
                logger.info("Deleting VM %s from netbox", netbox_vm_hostname)
                if not self.dry_run:
                    netbox_vm.delete()
                self.actions["VMs deleted"] += 1
            else:
                try:
                    diff_result = self.vm_diff(ganeti_instances[netbox_vm_hostname], netbox_vm)
                except KeyError as e:
                    logger.error("Failed to compare VM %s between Ganeti and Netbox: %s", netbox_vm_hostname, e)
                    continue
                if diff_result:
                    logger.info("Updating VM %s in Netbox", netbox_vm_hostname)
                    if not self.dry_run:
                        netbox_vm.save()
                    self.actions["VMs updated"] += 1

        for ganeti_instance_hostname, ganeti_instance in ganeti_instances.items():
            if ganeti_instance_hostname in netbox_vms:
                continue

            vm = cluster.create_vm(ganeti_instance)
            if vm:
                self.actions["VMs added"] += 1
            else:
                self.actions["VMs failed"] += 1

    def vm_diff(self, ganeti_instance: Dict, netbox_vm: pynetbox.models.virtualization.VirtualMachines) -> bool:
        """Update fields on netbox_vm from ganeti_instance, return True if updates are made."""
        updated = False
        for field in ("vcpus", "memory", "disk"):
            curr = getattr(netbox_vm, field)
            new = ganeti_instance[field]
            if curr != new:
                logger.debug("Updating %s on %s %d -> %d", field, netbox_vm.name, curr, new)
                setattr(netbox_vm, field, new)
                updated = True

        if netbox_vm.status.value != ganeti_instance["status"]:
            logger.debug(
                "Updating status on %s %d -> %d", netbox_vm.name, netbox_vm.status.value, ganeti_instance["status"]
            )
            netbox_vm.status = ganeti_instance["status"]
            updated = True

        return updated


def main() -> None:
    """Entry point for Ganeti->Netbox Sync."""
    args = parse_command_line_args()
    setup_logging(args.verbose, args.dry_run)

    cfg = ConfigParser()
    cfg.read(args.config)
    logger.info("Loaded %s configuration", args.config)

    session = wmflib_http_session(Path(__file__).name, timeout=(3, 15))

    profile_config = cfg[f"profile:{args.profile}"]
    ganeti = Ganeti(
        url=profile_config["cluster"],
        port=profile_config.get("port", "5080"),
        username=cfg["auth"]["ganeti_user"],
        password=cfg["auth"]["ganeti_password"],
        http_session=session,
    )

    netbox_api = pynetbox.api(cfg["netbox"]["api"], cfg["auth"]["netbox_token"], threading=True)
    netbox_api.http_session = session
    netbox = NetboxClusterGroup(
        api=netbox_api,
        cluster_group_name=args.profile,
        site=profile_config["site"],
        dry_run=args.dry_run,
    )

    syncer = GanetiNetboxSyncer(netbox, ganeti, dry_run=args.dry_run)
    syncer.sync()
    logger.info("Summary of performed actions: %s", syncer.actions)


if __name__ == "__main__":
    main()
