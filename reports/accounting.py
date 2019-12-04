"""
Checks the consistency of Netbox data against asset information in a Google
Sheet spreadsheet as maintained by Wikimedia Foundation's accounting
department.

Requires google-api-python-client and google-auth-oauthlib.
"""

import configparser
from collections import OrderedDict
from datetime import date, datetime, timedelta

from dcim.models import Device
from extras.reports import Report

import googleapiclient.discovery
from google.oauth2 import service_account

CONFIG_FILE = "/etc/netbox/gsheets.cfg"


class Accounting(Report):
    description = """
    Checks the consistency of Netbox data against the Data Center Equipment
    Asset Tags spreadsheet.
    """

    def __init__(self, *args, **kwargs):
        """Loads the config file and initializes the Google Sheets API."""
        config = configparser.ConfigParser(interpolation=None)
        config.read(CONFIG_FILE)

        self.assets = self.get_assets_from_accounting(
            config["service-credentials"], config["accounting"]["sheet_id"], config["accounting"]["range"]
        )

        super().__init__(*args, **kwargs)

    @staticmethod
    def get_assets_from_accounting(creds, sheet_id, range):
        """Retrieves all assets from a specified Google Spreadsheet."""

        # initialize the credentials API
        creds = service_account.Credentials.from_service_account_info(
            creds, scopes=["https://www.googleapis.com/auth/spreadsheets.readonly"]
        )

        # initialize the Sheets API
        service = googleapiclient.discovery.build("sheets", "v4", credentials=creds)
        sheet = service.spreadsheets()

        # and fetch the spreadsheet's contents
        result = sheet.values().get(spreadsheetId=sheet_id, range=range).execute()
        values = result.get("values", [])
        if not values:
            return values

        # ignore the first row, as it is the document header; the second row is
        # the header row, with column names, which we map here to our own names
        column_aliases = {
            # date of the invoice (US format, MM/DD/YYYY)
            "Date": "date",
            # serial number of the asset (used as unique key)
            "Serial Number": "serial",
            # asset tag of the asset ("WMFKKKK")
            "Asset Tag#": "asset_tag",
            # procurement ticket ("RT #NNNN" or "TMMMMM")
            "RT#": "ticket",
        }
        column_names = [column_aliases.get(name, name) for name in values[1]]

        # do some light parsing of the data, and store this in a dict keyed
        # by serial number, as this is the key we use for matching
        assets = OrderedDict()
        for row in values[2:]:
            # skip rows with merged columns, like page header, date sections etc.
            if len(row) < len(column_names):
                continue

            # use the column names for a dict's keys and the row as values
            asset = dict(zip(column_names, row))

            asset["date"] = datetime.strptime(asset["date"], "%m/%d/%Y").date()
            serial = asset["serial"]
            asset_tag = asset["asset_tag"]

            # skip items without a serial number; we use that as key to compare
            if serial.upper() in ("N/A", ""):
                continue

            # skip items that have been received, but later returned (blackout)
            if asset_tag.title() == "Return":
                if serial in assets:
                    del assets[serial]
                continue

            # TODO: we need to do the same with assets that are written off,
            # but there is currently no support in the spreadsheet for that.
            # We can do e.g. a separate line ("Recycled"), a separate column
            # or a separate sheet; cross that bridge when we come to it.

            # skip items we *explicitly* don't track, like e.g. hard disks
            if asset_tag.upper() == "WMFNA":
                continue

            # duplicate serial!
            # mark it with a suffix, so that serial checks pick it up and warn
            while serial in assets:
                serial = serial + " (duplicate)"

            assets[serial] = asset

        return assets

    def test_field_match(self):
        """Tests whether various fields match between Accounting and Netbox."""

        devices = {}
        qs = Device.objects.filter(serial__in=self.assets.keys())
        qs = qs.prefetch_related("custom_field_values__field")
        for device in qs:
            devices[device.serial] = device

        asset_tag_matches = ticket_matches = 0
        for serial, asset in self.assets.items():
            asset_tag = asset["asset_tag"]
            ticket = asset["ticket"]

            try:
                device = devices[serial]
            except KeyError:
                self.log_failure(
                    None,
                    "Device with s/n {serial} ({asset_tag}) not present in Netbox".format(
                        serial=serial, asset_tag=asset_tag
                    ),
                )
                continue

            if asset_tag != device.asset_tag:
                self.log_failure(
                    device,
                    "Asset tag mismatch for s/n "
                    + "{serial}: {asset_tag} (Accounting) vs. {netbox_asset_tag} (Netbox)".format(
                        serial=serial, asset_tag=asset_tag, netbox_asset_tag=device.asset_tag
                    ),
                )
            else:
                asset_tag_matches += 1

            # this is a rather convoluted way of fetching a custom field: this
            # is the equivalent of device.cf()["ticket"]. However, this way,
            # combined with the prefetch_related of custom_field_values__field
            # above, eliminates hundreds of queries and, consequently, makes
            # this 10-20x faster. There is likely a shorter way to do this, I
            # just haven't found it yet.
            netbox_ticket = None
            for cfv in device.custom_field_values.all():
                if cfv.field.name == "ticket":
                    netbox_ticket = cfv.value
                    break

            if ticket != netbox_ticket:
                self.log_warning(
                    device,
                    "Ticket mismatch for s/n {serial}: {ticket} (Accounting) vs. {netbox_ticket} (Netbox)".format(
                        serial=serial, ticket=ticket, netbox_ticket=netbox_ticket
                    ),
                )
            else:
                ticket_matches += 1

        self.log_success(None, "{} asset tags and {} tickets matched".format(asset_tag_matches, ticket_matches))

    def test_missing_assets_from_accounting(self):
        """Searches for assets that are in Netbox but not in Accounting."""

        # the spreadsheet starts at FY17-18
        oldest_date = date(2017, 7, 1)

        # allow some buffer time for newest assets to be shipped and invoice processed
        newest_date = date.today() - timedelta(90)

        recent_devices = Device.objects.exclude(serial="").filter(
            custom_field_values__field__name="purchase_date",
            custom_field_values__serialized_value__range=(oldest_date, newest_date),
        )

        device_matches = 0
        for device in recent_devices:
            if device.serial not in self.assets:
                self.log_failure(
                    device,
                    "Device with s/n {serial} ({asset_tag}) not present in Accounting".format(
                        serial=device.serial, asset_tag=device.asset_tag
                    ),
                )
            else:
                device_matches += 1

        self.log_success(None, "{} devices ({} to {}) matched".format(device_matches, oldest_date, newest_date))
