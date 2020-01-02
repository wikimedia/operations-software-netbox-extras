#!/usr/bin/env python3
"""Generate DNS zonefile snippets with records from Netbox to be included in zonefiles.

Todo:
    * For IPv4 sub /24 netmasks, get the largest one from Netbox instead of that of the interface.
    * Support a two-phase push to integrate with a cookbook.
    * Investigate dnspython instead of doing non-abstract string manipulations.

"""
import argparse
import ipaddress
import json
import logging
import os
import shutil
import sys
import tempfile

from collections import defaultdict, namedtuple
from configparser import ConfigParser
from pathlib import Path
from typing import DefaultDict, Dict, List, Mapping, Optional, Sequence, TextIO, Tuple

import git
import pynetbox

from git.util import get_user_id


logger = logging.getLogger()
GIT_USER_NAME = 'generate-dns-snippets'
GIT_USER_EMAIL = 'noc@wikimedia.org'
NETBOX_DEVICE_STATUSES = (1, 2, 3, 4, 6)  # Active, Planned, Staged, Failed, Decommissioning
DIRECT_LJUST_LEN = 40  # Fixed justification to avoid large diffs
NO_CHANGES_RETURN_CODE = 99
WARNING_PERCENTAGE_LINES_CHANGED = 3
ERROR_PERCENTAGE_LINES_CHANGED = 5
WARNING_PERCENTAGE_FILES_CHANGED = 8
ERROR_PERCENTAGE_FILES_CHANGED = 15
Record = namedtuple('Record', ('zone', 'reverse_zone', 'hostname', 'ip', 'reverse_ip'))


def setup_logging(verbose: bool = False) -> None:
    """Setup the logging with a custom format."""
    if not verbose:
        level = logging.INFO
        logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level=level, stream=sys.stderr)
    else:
        level = logging.DEBUG
        logging.basicConfig(
            format='%(asctime)s [%(levelname)s] %(pathname)s:%(lineno)s %(message)s', level=level, stream=sys.stderr
        )

    logging.getLogger('requests').setLevel(logging.WARNING)  # Silence noisy logger


def parse_args(args: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Setup command line argument parser and return parsed args.

    Arguments:
        args (list, optional): an optional list of CLI arguments to parse.

    Returns:
        argparse.Namespace: The resulting parsed arguments.

    """
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-c', '--config', help='The config file to load.', default='/etc/netbox/dns.cfg')
    parser.add_argument('-v', '--verbose', help='Verbose mode.', action='store_true')
    parser.add_argument('-b', '--batch', action='store_true',
                        help=('Enable the non-interactive mode, the commit will not be pushed to its remote and the '
                              'temporary directory will not be deleted. A JSON with the path of the temporary '
                              'directory and the SHA1 of the commit will be printed to the last line of stdout.'))
    parser.add_argument('message', help='The commit message to use.')

    return parser.parse_args(args)


def get_netbox_devices(config: ConfigParser) -> DefaultDict[str, Dict]:
    """Get the DNS records to generate from Netbox."""
    logger.info('Gathering devices, interfaces and addresses from Netbox')
    devices = defaultdict(lambda: {'addresses': set()})  # type: DefaultDict
    api = pynetbox.api(url=config.get('netbox', 'api'), token=config.get('netbox', 'token_ro'))
    addresses = {addr.id: addr for addr in api.ipam.ip_addresses.all()}

    for device in api.dcim.devices.filter(status=list(NETBOX_DEVICE_STATUSES)):
        devices[device.name]['device'] = device
        if device.primary_ip4 is not None:
            devices[device.name]['addresses'].add(addresses[device.primary_ip4.id])
        if device.primary_ip6 is not None:
            devices[device.name]['addresses'].add(addresses[device.primary_ip6.id])

    for address in addresses.values():
        if address.interface.device.name not in devices:
            logger.warning('Device %s of IP %s not in devices, skipping.', address.interface.device.name, address)
            continue

        if not address.dns_name:
            logger.warning('%s:%s has no DNS name', address.interface.device.name, address.interface.name)
            continue

        devices[address.interface.device.name]['addresses'].add(address)

    logger.info('Gathered %d devices from Netbox', len(devices))
    return devices


def split_dns_name(dns_name: str) -> Tuple[str, str]:
    """Given a FQDN split it into hostname and zone."""
    parts = dns_name.strip().split('.')
    max_len = 2
    if 'frack' in parts:
        max_len += 1
    if 'mgmt' in parts:
        max_len += 1

    split_len = min(len(parts) - 1, max_len)
    hostname = '.'.join(parts[:-split_len])
    zone = '.'.join(parts[-split_len:])

    return hostname, zone


def generate_records(devices: Mapping, min_records: int) -> Dict[str, DefaultDict[str, List[Record]]]:
    """Generate direct and reverse records based on Netbox data."""
    logger.info('Generating DNS records')
    records = {'direct': defaultdict(list), 'reverse': defaultdict(list)}  # type: Dict
    records_count = 0
    for name, device_data in devices.items():
        for address in device_data['addresses']:
            hostname, zone = split_dns_name(address.dns_name)
            reverse_zone, record_objects = generate_address_records(zone, hostname, address, device_data['device'])
            if record_objects:
                records['direct'][zone].extend(record_objects)
                records['reverse'][reverse_zone].extend(record_objects)
                records_count += len(record_objects)

    logger.info('Generated %d direct and reverse records (%d each) in %d direct zones and %d reverse zones',
                records_count * 2, records_count, len(records['direct']), len(records['reverse']))

    if records_count < min_records:
        logger.error(
            'CAUTION: the generated records are less than the minimum limit of %d. Check the diff!', min_records)

    return records


def generate_address_records(zone: str, hostname: str, address: pynetbox.models.ipam.IpAddresses,
                             device: pynetbox.models.dcim.Devices) -> Tuple[str, List[Record]]:
    """Generate Record objects for the given address."""
    interface = ipaddress.ip_interface(address.address)
    ip = interface.ip
    if ip.version == 6:  # For IPv6 PTRs we always split the zone at /64 and write the last 16 nibbles
        reverse_parts = ip.reverse_pointer.split('.')
        reverse_ip = '.'.join(reverse_parts[:16])
        reverse_zone = '.'.join(reverse_parts[16:])
    else:
        # For IPv4 PTRs we always write the last octet and by default split at the /24 boundary.
        # For non-octet boundary sub-24 netmasks RFC 2317 suggestions are followed, using the hyphen '-'
        # as separator for the netmask instead of the slash '/'.
        reverse_ip, reverse_zone = ip.reverse_pointer.split('.', 1)
        netmask = int(address.address.split('/')[1])
        if netmask > 24:
            reverse_zone = interface.network.reverse_pointer.replace('/', '-')

    records = []
    if device.status.label != 'Decommissioning':
        # Decomissioning hosts must have only the mgmt record for the asset tag
        records.append(Record(zone, reverse_zone, hostname, ip, reverse_ip))

    # Generate the additional asset tag mgmt record only if the Netbox name is not the asset tag already
    if address.interface.name == 'mgmt' and device.name.lower() != device.asset_tag.lower():
        records.append(Record(zone, reverse_zone, device.asset_tag.lower(), ip, reverse_ip))

    return reverse_zone, records


def setup_repo(config: ConfigParser, tmpdir: str) -> git.Repo:
    """Setup the git repository working clone."""
    repo_path = config.get('dns_snippets', 'repo_path')
    logger.info('Cloning %s to %s ...', repo_path, tmpdir)
    origin_repo = git.Repo(repo_path)
    working_repo = origin_repo.clone(tmpdir)

    return working_repo


def write_direct_records(zonefile: TextIO, records: Sequence[Record]) -> None:
    """Write direct records to the given zonefile."""
    for record in sorted(records, key=lambda record: (record.hostname, record.ip.exploded)):
        zonefile.write('{hostname} 1H IN {record_type} {ip}\n'.format(
            hostname=record.hostname.ljust(DIRECT_LJUST_LEN),
            record_type='AAAA' if record.ip.version == 6 else 'A',
            ip=record.ip.compressed))


def write_reverse_records(zonefile: TextIO, records: Sequence[Record]) -> None:
    """Write reverse records to the given zonefile."""
    for record in sorted(records, key=lambda r: [int(i) for i in r.reverse_ip.split('.')] + [r.hostname]):
        zonefile.write('{reverse_ip} 1H IN PTR {hostname}.{zone}.\n'.format(
            reverse_ip=record.reverse_ip.ljust(3), hostname=record.hostname, zone=record.zone))


def generate_snippets(records: Mapping[str, Mapping[str, Sequence[Record]]], tmpdir: str) -> None:
    """Generate the DNS snippet files."""
    logger.info('Generating zonefile snippets to tmpdir %s', tmpdir)
    for record_type, zones in records.items():
        for zone, zone_records in zones.items():
            with open(os.path.join(tmpdir, zone), 'w') as zonefile:
                if record_type == 'direct':
                    write_direct_records(zonefile, zone_records)
                else:
                    write_reverse_records(zonefile, zone_records)

            logger.debug('Wrote %d %s records in %s zonefile', len(zone_records), record_type, zone)


def get_file_stats(tmpdir: str) -> Tuple[int, int]:
    """Get file stats of the checkout."""
    lines = 0
    files = 0
    path = Path(tmpdir)
    for zone in path.glob('[!.]*'):
        files += 1
        with open(zone) as f:
            lines += sum(1 for line in f)

    logger.debug('Found %d existing files with %d lines', files, lines)
    return files, lines


def commit_changes(args: argparse.Namespace, working_repo: git.Repo) -> Optional[git.objects.commit.Commit]:
    """Add local changes and commit them, if any."""
    working_repo.index.add('*')
    if working_repo.head.is_valid() and not working_repo.index.diff(working_repo.head.commit):
        logger.info('Nothing to commit!')
        return None

    author = git.Actor(GIT_USER_NAME, GIT_USER_EMAIL)
    message = '{user}: {message}'.format(user=get_user_id(), message=args.message)
    commit = working_repo.index.commit(message, author=author, committer=author)
    logger.info('Committed changes: %s', commit.hexsha)

    return commit


def validate_delta(changed: int, existing: int, warning: int, error: int, what: str) -> None:
    """Validate the percentage of changes and alert the user if over a threshold."""
    if existing == 0:
        return

    delta = changed * 100 / existing
    if delta > error:
        logging.error('CAUTION: %.1f%% of %s modified is over the error thresold. Check the diff!', delta, what)
    elif delta > warning:
        logging.warning('%.1f%% of %s modified is over the warning thresold', delta, what)
    else:
        logger.debug('%.1f%% of %s modified', delta, what)


def validate(files: int, lines: int, delta: Mapping[str, int]) -> None:
    """Validate the generated data."""
    logging.info('Validating generated data')
    validate_delta(delta['files'], files, WARNING_PERCENTAGE_FILES_CHANGED, ERROR_PERCENTAGE_FILES_CHANGED, 'files')
    validate_delta(delta['lines'], lines, WARNING_PERCENTAGE_LINES_CHANGED, ERROR_PERCENTAGE_LINES_CHANGED, 'lines')


def run(args: argparse.Namespace, config: ConfigParser, tmpdir: str) -> int:
    """Generate and commit the DNS snippets."""
    devices = get_netbox_devices(config)
    records = generate_records(devices, config.getint('dns_snippets', 'min_records'))
    working_repo = setup_repo(config, tmpdir)
    files, lines = get_file_stats(tmpdir)
    working_repo.git.rm('.', r=True, ignore_unmatch=True)  # Delete all existing files to ensure removal of stale files
    generate_snippets(records, tmpdir)
    commit = commit_changes(args, working_repo)

    if commit is None:
        if args.batch:
            print(json.dumps({'no_changes': True}))
        return NO_CHANGES_RETURN_CODE

    print(working_repo.git.show(['--color=always', 'HEAD']))
    validate(files, lines, commit.stats.total)

    if args.batch:
        print(json.dumps({'path': tmpdir, 'sha1': commit.hexsha}))
        return 0

    answer = input('OK to push the changes to the {origin} repository? (y/n) '.format(
        origin=config.get('dns_snippets', 'repo_path')))
    if answer == 'y':
        push_info = working_repo.remote().push()[0]
        if push_info.flags & push_info.ERROR == push_info.ERROR:
            level = logging.ERROR
            exit_code = 2
        else:
            level = logging.INFO
            exit_code = 0

        logger.log(level, 'Pushed with bitflags %d: %s %s',
                   push_info.flags, push_info.summary.strip(), commit.stats.total)

    else:
        logger.error('Manually aborted.')
        exit_code = 3

    return exit_code


def main() -> int:
    """Execute the script."""
    args = parse_args()
    setup_logging(args.verbose)
    config = ConfigParser()
    config.read(args.config)

    tmpdir = tempfile.mkdtemp(prefix='dns-snippets-')
    try:
        exit_code = run(args, config, tmpdir)

    except Exception:
        logger.exception('Failed to run')
        exit_code = 1

    finally:
        if exit_code not in (0, NO_CHANGES_RETURN_CODE):
            print('An error occurred, the generated files can be inspected in {tmpdir}'.format(tmpdir=tmpdir))
            input('Press any key to cleanup the generated files and exit ')

        if not args.batch or exit_code == NO_CHANGES_RETURN_CODE:
            shutil.rmtree(tmpdir, ignore_errors=True)

    return exit_code


if __name__ == '__main__':
    sys.exit(main())
