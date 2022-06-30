# """Dump various Netbox tables to CSV format."""

import argparse
import csv
import io
import json
import logging
import os
import sys
import time

import pynetbox

from functools import wraps
from configparser import ConfigParser

logger = logging.getLogger()

# These are the default for dumping all tables
ALL_TABLES = {
    "dcim.sites",
    "dcim.regions",
    "tenancy.tenants",
    "dcim.racks",
    "dcim.locations",
    "dcim.devices",
    "dcim.devices.custom_fields",
    "dcim.device_roles",
    "dcim.platforms",
    "dcim.device_types",
    "dcim.manufacturers",
    "dcim.cables",
    "dcim.inventory_items",
    "dcim.interfaces",
    "ipam.ip_addresses",
    "ipam.prefixes",
    "ipam.aggregates",
    "ipam.rirs",
    "ipam.vlans",
    "ipam.vlan_groups",
    "virtualization.interfaces",
    "virtualization.virtual_machines",
    "virtualization.virtual_machines.custom_fields",
    "virtualization.clusters",
    "virtualization.cluster_types",
    # "virtualization.cluster_groups",  # Temporarily disabled as the current pynetbox fails with the custom field
    "circuits.circuits",
    "circuits.circuit_types",
    "circuits.providers",
    "devices_full",
}

# These are some convenient aliases for longer path names
TABLE_ALIASES = {
    "devices_custom_fields": "dcim.devices.custom_fields",
    "virtual_machines_custom_fields": "virtualization.virtual_machines.custom_fields",
}


def retry(exception, attempts=1, cooldown=1):
    """A decorator which will retry a runable and catch potential exceptions.

    Arguments:
       exception (class or tuple of classes): The exception class to catch
       attempts (integer): the number of tries to attempt to run the function
       cooldown (float): the number of seconds to sleep between attempts.
    """

    def retry_decorator(func):
        @wraps(func)
        def retry_internal(*args, **kwargs):
            _attempts = attempts
            while _attempts > 0:
                try:
                    return func(*args, **kwargs)
                except exception as e:
                    logger.info("%s failed with %s, try %d, retrying in %f seconds", func, e, _attempts, cooldown)
                _attempts -= 1
                time.sleep(cooldown)
            return func(*args, **kwargs)

        return retry_internal

    return retry_decorator


class DataTable:
    """A wrapper for a list of dictionaries which can output in various formats."""

    def __init__(self, dicts):
        """Initialize.

        Arguments:
            dicts (list): A list of dictionaries.

        """
        self._dicts = dicts

    def to_csv(self, *csvargs, **kwcsvargs):
        """Dump the dictionaries as rows in a CSV file.

        Arguments:
            *args, **kwargs: Override arguments to the CSV writer.

        Returns:
            str: CSV formatted data rows separated by \n.

        """
        fieldnames = set()
        for row in self._dicts:
            [fieldnames.add(x) for x in row.keys()]

        csvdefaultkwargs = {"fieldnames": list(sorted(fieldnames))}
        csvdefaultkwargs.update(kwcsvargs)

        output = io.StringIO()
        writer = csv.DictWriter(output, *csvargs, **csvdefaultkwargs)
        writer.writeheader()
        for row in self._dicts:
            writer.writerow(row)
        return output.getvalue()

    def to_json(self):
        """Dump the dictionaries as JSON."""
        return json.dumps(self._dicts)


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

    parser.add_argument("output", help="The path to output the CSV files to.")
    parser.add_argument(
        "-c",
        "--config",
        help="The path to the config file to load. Default: %(default)s.",
        default="/etc/netbox/scripts.cfg",
    )
    parser.add_argument("-v", "--verbose", help="Output more verbosity.", action="store_true")

    def format_digest(value):
        # work around some command-line parser limitations...
        ret = []
        for fmt in value.split(","):
            if fmt not in ("csv", "json"):
                raise argparse.ArgumentTypeError("Format must be one of csv, json")
            ret.append(fmt)
        return ret

    parser.add_argument(
        "-f",
        "--format",
        help="Choose which format(s) to output (comma-separated) Options: csv or json Default: %(default)s",
        default="csv",
        type=format_digest,
    )

    parser.add_argument("-m", "--makedir", help="Create the path specified. Default: %(default)s", action="store_true")
    parser.add_argument(
        "-t",
        "--tables",
        help=(
            "A comma separated list of tables (expressed as API path similar to `dcim.device`) to include in the dump"
            ", or the special value `all`."
        ),
        default="all",
        type=lambda arg: arg.split(","),
    )
    args = parser.parse_args()
    return args


def get_endpoint_obj(api, apipath):
    """Returns an Endpoint object within a Netbox API object for a given path.

    Arguments:
        api (:obj:`pynetbox.Api`): An initialized API object.
        apipath (str): A dotted path to the API desired.

    Returns:
        :obj:`pynetbox.Endpoint: An Endpoint object for the specified path.

    """
    logger.debug("getting endpoint for {}".format(apipath))
    endpoints = apipath.split(".")
    app = api.__getattribute__(endpoints[0])
    for ep in endpoints[1:]:
        app = app.__getattr__(ep)
    return app


@retry(pynetbox.core.query.RequestError, attempts=3, cooldown=0.5)
def handle_generic(api, tablename):
    """Return the data for a specific table name.

    This function specifically excludes any present custom fields.

    Arguments:
        api (obj): An initialized pynetbox API object
        tablename: The name of the table to dump.

    Returns:
        :obj:`DataTable`: A table of data for the specified table name.

    """
    logger.debug("getting all data for table {}".format(tablename))
    endpoint = get_endpoint_obj(api, tablename)
    alldata = []
    for row in endpoint.all():
        dat = row.serialize()
        # Ignore lines with empty names (breaks the sorting below) - T275587
        if 'name' in dat and not dat['name']:
            continue
        if "custom_fields" in dat:
            del dat["custom_fields"]
        alldata.append(dat)
    logger.debug("got {} records for table {}".format(len(alldata), tablename))

    if alldata:
        if "name" in alldata[0]:
            sortfield = "name"
        elif "id" in alldata[0]:
            sortfield = "id"
        else:
            sortfield = sorted(alldata[0].keys())[0]
        logger.debug("using {} as sort field".format(sortfield))
        return DataTable(sorted(alldata, key=lambda x: x[sortfield]))
    return None


def process_custom_fields(customfields):
    """Perform some minor processing on customfields dictionaries so that they spread out into csv columns more
    conveniently.

    Arguments:
        customfields (dict): A similar to customfields from Netbox.

    Returns:
        dict: The post-process customfields.

    """
    additional = {}
    removals = []
    for key, value in customfields.items():
        if isinstance(value, dict):
            removals.append(key)
            # selection values are stored as dicts, but we"ll try to smartly translate dicts, leaving
            # the actual column as the "value" of the selection.
            for datkey in value:
                additional[key + "_" + datkey] = value[datkey]
                if "value" in value:
                    additional[key] = value["value"]
    customfields.update(additional)
    for key in removals:
        del customfields[key]
    return customfields


@retry(pynetbox.core.query.RequestError, attempts=3, cooldown=0.5)
def handle_custom_fields(api, tablename):
    """Return the data for the custom fields associated with a specific table.

    Arguments:
        api (obj): An initialized pynetbox API object
        tablename: The name of the table whose custom fields to dump.

    Returns:
        :obj:`DataTable`: A table of data for the specified table name"s custom fields.

    """
    logger.debug("getting custom fields for table {}".format(tablename))
    if tablename.endswith(".custom_fields"):
        endpoint = get_endpoint_obj(api, tablename[:-14])
    else:
        endpoint = get_endpoint_obj(api, tablename)
    alldata = []
    for row in endpoint.all():
        if row.custom_fields:
            customfields = process_custom_fields(row.custom_fields)
            if customfields is not None:
                customfields["parent_id"] = row.id
                alldata.append(customfields)
    if alldata:
        return DataTable(sorted(alldata, key=lambda x: x['parent_id']))

    return None


@retry(pynetbox.core.query.RequestError, attempts=3, cooldown=0.5)
def handle_devices_full(api, *args, **kwargs):
    """Return the data for the devices table.

    This function also creates columns in each device for the rack name, location, manufactuerer information, etc.
    as useful strings / slugs.

    Arguments:
        api (obj): An initialized pynetbox API object

    Returns:
        :obj:`DataTable`: A table of data for the specified table name.

    """
    alldata = []

    # Prefetch a bunch of dependency data.
    racks = retry(pynetbox.core.query.RequestError)(api.dcim.racks.all)()
    sites = retry(pynetbox.core.query.RequestError)(api.dcim.sites.all)()
    site_data = {site.id: site.slug for site in sites}
    rack_data = {rack.id: {"name": rack.name, "site": site_data[rack.site.id]} for rack in racks}
    device_types = retry(pynetbox.core.query.RequestError)(api.dcim.device_types.all)()
    device_type_data = {
        device_type.id: {
            "manufacturer": device_type.manufacturer.slug,
            "height": device_type.u_height,
            "slug": device_type.slug,
        }
        for device_type in device_types
    }
    for device in api.dcim.devices.all():
        row = device.serialize()
        # Digest foreign keys into slugs or other useful things.
        if device.custom_fields:
            row["custom_fields"] = process_custom_fields(device.custom_fields)
        if row["rack"]:
            row["rack_site"] = rack_data[row["rack"]]["site"]
            row["rack_name"] = rack_data[row["rack"]]["name"]
            if device.face:
                row["rack_face"] = device.face.label
            row["rack_position"] = device.position
        row["site"] = site_data[row["site"]]
        if device.tenant:
            row["tenant"] = device.tenant.slug
        row["device_manufacturer"] = device_type_data[row["device_type"]]["manufacturer"]
        row["device_height"] = device_type_data[row["device_type"]]["height"]
        row["device_type"] = device_type_data[row["device_type"]]["slug"]
        row["status"] = device.status.label
        del row["platform"]
        if device.platform:
            row["platform"] = device.platform.slug
        row["device_role"] = device.device_role.slug

        del row["position"]
        del row["rack"]
        del row["face"]

        alldata.append(row)

    if alldata:
        return DataTable(sorted(alldata, key=lambda x: x['name']))

    return None


# These define which handler to use for any given table name, with `*` the default.
# We have to define this constant down here because the functions are defined above.
HANDLERS = {
    "*": handle_generic,
    "devices_full": handle_devices_full,
    "virtualization.virtual_machines.custom_fields": handle_custom_fields,
    "dcim.devices.custom_fields": handle_custom_fields,
}


def main():
    """Main function."""
    args = parse_args()
    setup_logging(args.verbose)

    config = ConfigParser()
    config.read(args.config)
    netbox_token = config["netbox"]["token_ro"]
    netbox_api = config["netbox"]["api"]

    api = pynetbox.api(url=netbox_api, token=netbox_token)

    if args.makedir:
        logger.debug("Making output directory {}".format(args.output))
        os.makedirs(args.output, exist_ok=True)

    if "all" in args.tables:
        logger.info("Outputting all tables to {}".format(args.output))
        tables = ALL_TABLES
    else:
        logger.info("Outputting tables {} to {}".format(str(args.tables), args.output))
        tables = {TABLE_ALIASES[x] if x in TABLE_ALIASES else x for x in args.tables}

    for table in tables:
        handler = HANDLERS.get(table, HANDLERS["*"])

        logger.debug("Calling handler {} for {}".format(str(handler), table))
        data = handler(api, table)
        if data:
            for fmt in set(args.format):
                filename = "{}.{}".format(table, fmt)
                outputter = {"csv": data.to_csv, "json": data.to_json}[fmt]
                logger.info("Outputting to {}".format(filename))
                with open(os.path.join(args.output, filename), "w") as output:
                    output.write(outputter())
        else:
            logger.info("No data for {}, skipping.".format(table))

    return 0


if __name__ == "__main__":
    sys.exit(main())
