#!/usr/bin/env python3
"""Synchronize Ganeti data to Netbox."""
import argparse
import logging

from collections import Counter
from configparser import ConfigParser
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Callable, Counter as CounterType, Dict, List, Optional

import pynetbox
import requests

from wmflib.requests import http_session


NO_PUPPETDB_VMS = ('d-i-test',)
logger = logging.getLogger()


def parse_command_line_args() -> argparse.Namespace:
    """Parse command line options."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('profile', help='The profile to use from the configuration file.')
    parser.add_argument('-c', '--config', default='/etc/netbox/ganeti-sync.cfg',
                        help='The path to the config file to load.')
    parser.add_argument('-d', '--dry-run', action='store_true',
                        help="Don't actually commit any changes, just do a dry-run")
    parser.add_argument('-v', '--verbose', help='Output more verbosity.', action='store_true')

    args = parser.parse_args()

    if args.dry_run:
        args.verbose = True

    return args


def setup_logging(verbose: bool = False, dry_run: bool = False) -> None:
    """Setup the logging with a custom format to go to stdout."""
    level = logging.DEBUG if verbose else logging.INFO
    requests_level = logging.INFO if verbose else logging.WARNING
    prefix = 'DRY-RUN ' if dry_run else ''
    logging.basicConfig(format=f'%(asctime)s [%(levelname)s] {prefix}%(message)s', level=level)
    logging.getLogger('requests').setLevel(requests_level)  # Silence noisy logger


@dataclass
class Ganeti:
    """Class to fetch data from the Ganeti API to populate Netbox."""

    url: str
    port: str
    username: str
    password: str
    ca_cert: str
    http_session: requests.sessions.Session

    def _query(self, endpoint: str) -> Dict:
        """GET the provided endpoint from the Ganeti API."""
        response = self.http_session.get(
            f'https://{self.url}:{self.port}/2/{endpoint}',
            auth=requests.auth.HTTPBasicAuth(self.username, self.password),
            verify=self.ca_cert)

        if response.status_code != requests.codes.ok:
            raise RuntimeError(f'Ganeti API call to {endpoint} failed with {response.status_code}:\n{response.text}')

        return response.json()

    def get_instances(self) -> Dict:
        """Return the instances of the current cluster."""
        instances = {}
        for instance in self._query('instances?bulk=1'):
            try:
                name = instance['name'].split('.', 1)[0]
                instances[name] = {
                    'name': name,
                    'vcpus': instance['beparams']['vcpus'],
                    'memory': instance['beparams']['memory'],
                    'disk': round(sum(instance['disk.sizes']) / 1024, 0),  # Ganeti returns MB, Netbox expects GB
                    'status': 'active' if instance['admin_state'] == 'up' else 'offline',
                }
            except (KeyError, TypeError) as e:
                logger.error('Failed to get data for Ganeti instance %s: %s', name, e)
                continue

        logger.debug('Loaded %d Ganeti instances in cluster %s', len(instances), self.url)
        return instances

    def get_nodes(self) -> List:
        """Return the nodes of the current cluster."""
        nodes = [node['id'].split('.', 1)[0] for node in self._query('nodes')]
        logger.debug('Loaded %d Ganeti nodes in cluster %s', len(nodes), self.url)
        return nodes


@dataclass
class NetboxCluster:
    """Class to manage Netbox clusters."""

    url: str
    token: str
    cluster: str
    http_session: requests.sessions.Session
    dry_run: bool

    def __post_init__(self) -> None:
        """Initialize additional instance variables."""
        self._api = pynetbox.api(self.url, token=self.token)
        self.linux_id = self._api.dcim.platforms.get(slug='linux').id
        self.cluster_id = self._api.virtualization.clusters.get(name=self.cluster).id
        self.server_id = self._api.dcim.device_roles.get(slug='server').id

    def _create_resource(self, resource: str, func: Callable, data: Dict) -> bool:
        """Create a resource, dry-run aware. Returns True if successfully created."""
        name = data['name']
        logger.info('Creating %s %s with data: %s', resource, name, data)
        if self.dry_run:
            return True

        try:
            created = func(data)
        except pynetbox.RequestError as e:
            logger.error('Failed to create %s %s in Netbox: %s', resource, name, e)
            created = False

        return created

    def puppetdb_import(self) -> None:
        """Execute PuppetDB import on any host that have the placeholder PRIMARY interface."""
        reimport = [str(iface.virtual_machine) for iface in
                    self._api.virtualization.interfaces.filter(name='##PRIMARY##', cluster=self.cluster)
                    if iface.virtual_machine.name not in NO_PUPPETDB_VMS]
        if not reimport:
            return

        logger.info('Running PuppetDB import script for %d VMs.', len(reimport))
        url = f'{self.url}api/extras/scripts/interface_automation.ImportPuppetDB/'
        headers = {'Authorization': f'Token {self.token}'}
        data = {'data': {'device': ' '.join(reimport)}, 'commit': not self.dry_run}
        result = self.http_session.post(url, headers=headers, json=data)
        if result.status_code == 200:
            logger.debug('Executed import, result: %s', result.text)
        else:
            logger.error('Error executing PuppetDB import: %s', result.text)

    def get_vms(self) -> Dict:
        """Return all the VMs for the current cluster."""
        vms = {vm.name: vm for vm in self._api.virtualization.virtual_machines.filter(cluster=self.cluster_id)}
        logger.debug('Loaded %d Netbox VMs in cluster %s', len(vms), self.cluster)
        return vms

    def get_devices(self) -> Dict:
        """Return all the physical devices that are part of the current cluster."""
        devices = {device.name: device for device in self._api.dcim.devices.filter(cluster_id=self.cluster_id)}
        logger.debug('Loaded %d Netbox devices in cluster %s', len(devices), self.cluster)
        return devices

    def create_vm(self, data: Dict) -> bool:
        """Create a VM with the given data and return a boolean that tells if it was created successfully."""
        data.update({'cluster': self.cluster_id, 'platform': self.linux_id, 'role': self.server_id})
        return self._create_resource('VM', self._api.virtualization.virtual_machines.create, data)

    def _set_device_cluster(self, device_name: str, cluster_id: Optional[int]) -> bool:
        """Update a device setting the cluster ID."""
        try:
            device = self._api.dcim.devices.get(name=device_name)
        except pynetbox.RequestError as e:
            logger.error('Unable to load device %s on Netbox: %s', device, e)
            return False

        logger.info('Setting cluster ID to %s for device %s', cluster_id, device)
        if self.dry_run:
            return True

        try:
            device.cluster = cluster_id
            device.save()
            return True
        except pynetbox.RequestError as e:
            logger.error('Failed to save Netbox device %s: %s', device, e)
            return False

    def add_device(self, device: str) -> bool:
        """Add a physical device to the current cluster."""
        return self._set_device_cluster(device, self.cluster_id)

    def remove_device(self, device: str) -> bool:
        """Remove a physical device from the current cluster."""
        return self._set_device_cluster(device, None)


@dataclass
class GanetiNetboxSyncer:
    """Class to perform the sync from Ganeti to Netbox."""

    netbox: NetboxCluster
    ganeti: Ganeti
    dry_run: bool
    actions: CounterType = dataclass_field(default_factory=Counter)

    def sync_vms(self) -> None:
        """Sync Ganeti VMs to Netbox."""
        ganeti_instances = self.ganeti.get_instances()
        netbox_vms = self.netbox.get_vms()
        for netbox_vm_hostname, netbox_vm in netbox_vms.items():
            if netbox_vm_hostname not in ganeti_instances:
                logger.debug('Deleting VM %s from netbox', netbox_vm_hostname)
                if not self.dry_run:
                    netbox_vm.delete()
                self.actions['VMs deleted'] += 1
            else:
                try:
                    diff_result = self.vm_diff(ganeti_instances[netbox_vm_hostname], netbox_vm)
                except KeyError as e:
                    logger.error('Failed to compare VM %s between Ganeti and Netbox: %s', netbox_vm_hostname, e)
                    continue
                if diff_result:
                    logger.debug('Updating VM %s in Netbox', netbox_vm_hostname)
                    if not self.dry_run:
                        netbox_vm.save()
                    self.actions['VMs updated'] += 1

        for ganeti_instance_hostname, ganeti_instance in ganeti_instances.items():
            if ganeti_instance_hostname in netbox_vm_hostname:
                continue

            created = self.netbox.create_vm(ganeti_instance)
            if created:
                self.actions['VMs added'] += 1
            else:
                self.actions['VMs failed'] += 1

    def sync_nodes(self) -> None:
        """Sync Ganeti nodes to Netbox to be member of the cluster devices."""
        ganeti_nodes = self.ganeti.get_nodes()
        netbox_devices = self.netbox.get_devices()

        for node in ganeti_nodes:
            if node in netbox_devices:
                continue

            created = self.netbox.add_device(node)
            if created:
                self.actions['Nodes added'] += 1
            else:
                self.actions['Nodes failed'] += 1

        for name, device in netbox_devices.items():
            if name in ganeti_nodes:
                continue

            deleted = self.netbox.remove_device(name)
            if deleted:
                self.actions['Nodes removed'] += 1
            else:
                self.actions['Nodes failed'] += 1

    def vm_diff(self, ganeti_instance: Dict, netbox_vm: pynetbox.models.virtualization.VirtualMachines) -> bool:
        """Update fields on netbox_vm from ganeti_instance, return True if updates are made."""
        updated = False
        for field in ('vcpus', 'memory', 'disk'):
            curr = getattr(netbox_vm, field)
            new = ganeti_instance[field]
            if curr != new:
                logger.debug('Updating %s on %s %d -> %d', field, netbox_vm.name, curr, new)
                setattr(netbox_vm, field, new)
                updated = True

        if netbox_vm.status.value != ganeti_instance['status']:
            logger.debug(
                'Updating status on %s %d -> %d', netbox_vm.name, netbox_vm.status.value, ganeti_instance['status'])
            netbox_vm.status = ganeti_instance['status']
            updated = True

        return updated


def main() -> None:
    """Entry point for Ganeti->Netbox Sync."""
    args = parse_command_line_args()
    setup_logging(args.verbose, args.dry_run)
    session = http_session(Path(__file__).name)

    cfg = ConfigParser()
    cfg.read(args.config)
    logger.info('Loaded %s configuration', args.config)

    profile_config = cfg[f'profile:{args.profile}']
    ganeti = Ganeti(
        url=profile_config['url'],
        port=profile_config['port'],
        username=cfg['auth']['ganeti_user'],
        password=cfg['auth']['ganeti_password'],
        ca_cert=cfg['auth']['ca_cert'],
        http_session=session,
    )
    netbox = NetboxCluster(
        url=cfg['netbox']['api'],
        token=cfg['auth']['netbox_token'],
        cluster=args.profile,
        http_session=session,
        dry_run=args.dry_run,
    )

    syncer = GanetiNetboxSyncer(netbox, ganeti, dry_run=args.dry_run)
    syncer.sync_nodes()
    syncer.sync_vms()
    netbox.puppetdb_import()
    logger.info('Summary of performed actions: %s', syncer.actions)


if __name__ == '__main__':
    main()
