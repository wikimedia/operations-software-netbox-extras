"""Accounting Netbox report.

Check the consistency of Netbox data against asset information in a Google
Sheet spreadsheet, as maintained by Wikimedia Foundation's accounting
department.

Requires google-api-python-client and google-auth-oauthlib.
"""

import configparser
from datetime import date, datetime, timedelta
from urllib.parse import urlparse

from dcim.models import Device
from extras.reports import Report
from netbox import configuration

import googleapiclient.discovery
from google.oauth2 import service_account
from google_auth_httplib2 import AuthorizedHttp
from httplib2 import Http, ProxyInfo
from httplib2.socks import PROXY_TYPE_HTTP

CONFIG_FILE = "/etc/netbox/gsheets.cfg"


class Accounting(Report):
    """Check the consistency of Netbox data against the Data Center Equipment Asset Tags spreadsheet."""

    description = __doc__

    def __init__(self):
        """Generic init."""
        self.assets = {}

    def run(self, job_results):
        """Load the config file and initializes the Google Sheets API."""
        config = configparser.ConfigParser(interpolation=None)
        config.read(CONFIG_FILE)

        self.assets = self.get_assets_from_accounting(
            config["service-credentials"],
            config["accounting"]["sheet_id"],
            config["accounting"]["include_range"],
            config["accounting"]["exclude_range"],
        )

        return super().run(job_results)

    @staticmethod
    def get_assets_from_accounting(creds, sheet_id, include_range, exclude_range):  # noqa: MC0001
        # pylint: disable-msg=too-many-locals

        # Disable the alerting as there is no point for now to work on simplifying the function
        """Retrieve all assets from a specified Google Spreadsheet."""
        # initialize the credentials API
        creds = service_account.Credentials.from_service_account_info(
            creds, scopes=["https://www.googleapis.com/auth/spreadsheets.readonly"]
        )
        try:
            proxy = urlparse(configuration.HTTP_PROXIES.get("https", configuration.HTTP_PROXIES["http"]))
            http = Http(proxy_info=ProxyInfo(PROXY_TYPE_HTTP, proxy.hostname, proxy.port))
        except (KeyError, AttributeError):
            # either no or badly formed HTTP_PROXIES
            http = Http()

        authorized_http = AuthorizedHttp(credentials=creds, http=http)
        service = googleapiclient.discovery.build("sheets", "v4", http=authorized_http)
        sheet = service.spreadsheets()

        # and fetch the spreadsheet's contents
        result = (
            sheet.values()
            .get(
                spreadsheetId=sheet_id,
                range=include_range,
                valueRenderOption="FORMULA",  # do not calculate formula values
                dateTimeRenderOption="FORMATTED_STRING",
            )
            .execute()
        )
        values = result.get("values", [])
        if not values:
            return values

        # fetch the recycled ones now
        recycled_result = (
            sheet.values()
            .get(
                spreadsheetId=sheet_id,
                range=exclude_range,
                valueRenderOption="FORMULA",  # do not calculate formula values
                dateTimeRenderOption="FORMATTED_STRING",
            )
            .execute()
        )
        recycled_values = recycled_result.get("values", [])
        recycled_serials = [str(row[0]).upper() for row in recycled_values[1:] if row[0]]

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
        assets = {}
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

            # skip items that have been recycled
            if serial.upper() in recycled_serials:
                continue

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
        for device in qs:
            devices[device.serial] = device

        asset_tag_matches = ticket_matches = 0
        for serial, asset in self.assets.items():
            asset_tag = asset["asset_tag"]
            asset_tag_is_formula = asset_tag.startswith("=NETBOX")
            ticket = asset["ticket"]

            try:
                device = devices[serial]
            except KeyError:
                if asset_tag_is_formula:
                    asset_tag = "N/A"
                self.log_failure(None, f"Device with s/n {serial} ({asset_tag}) not present in Netbox")
                continue

            if asset_tag_is_formula:
                # asset tag is set to a formula polling Netbox, so avoid pointlessly checking
                # if that matches, as well as the circular reference that takes a while to resolve
                pass
            elif asset_tag != device.asset_tag:
                self.log_failure(
                    device,
                    f"Asset tag mismatch for s/n {serial}: {asset_tag} (Accounting) vs. {device.asset_tag} (Netbox)",
                )
            else:
                asset_tag_matches += 1

            netbox_ticket = None
            if "ticket" in device.cf:
                netbox_ticket = device.cf["ticket"]

            if ticket != netbox_ticket:
                self.log_warning(
                    device, f"Ticket mismatch for s/n {serial}: {ticket} (Accounting) vs. {netbox_ticket} (Netbox)"
                )
            else:
                ticket_matches += 1

        self.log_success(None, f"{asset_tag_matches} asset tags and {ticket_matches} tickets matched")

    def test_missing_assets_from_accounting(self):
        """Searches for assets that are in Netbox but not in Accounting."""
        # the spreadsheet starts at FY17-18
        oldest_date = date(2017, 7, 1)

        # allow some buffer time for newest assets to be shipped and invoice processed
        newest_date = date.today() - timedelta(90)

        recent_devices = Device.objects.exclude(serial="").filter(
            custom_field_data__purchase_date__range=(oldest_date, newest_date)
        )

        device_matches = 0
        for device in recent_devices:
            if device.serial not in self.assets:
                self.log_failure(
                    device, f"Device with s/n {device.serial} ({device.asset_tag}) not present in Accounting"
                )
            else:
                device_matches += 1

        self.log_success(None, f"{device_matches} devices ({oldest_date} to {newest_date}) matched")
