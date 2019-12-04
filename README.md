# Wikimedia Netbox Extras #

This repository contains extra components used for Netbox at the Wikimedia Foundation.

# Reports #

All reports are contained in `reports/`.

The reports check various consistencies within Netbox data and between Netbox and other services.

* `reports/coherence.py`: Various "coherence" tests, basically ensuring that values are within expected ranges.
* `reports/management.py`: Tests the status of management console ports.
* `reports/oldhardware.py`: Tests the age of hardware based on the `purchase_date` custom field.
* `reports/puppetdb.py`: Tests the parity between Netbox and PuppetDB for various fields such as serial numbers.
* `reports/accounting.py`: Tests the consistency of Netbox data and asset information in a Google Sheet spreadsheet as maintained by Wikimedia Foundation's accounting department.
* `reports/cables.py`: Ensures that all cable terminations have names within a certain set of values.
* `reports/librenms.py`: Tests the consistency of Netbox data against LibreNMS's view of the network (with many site-specific caveats and exceptions).

## Conventions and Contributing ##

The general conventions for the output of reports are specified in
[Wikitech's Netbox Page](https://wikitech.wikimedia.org/wiki/Netbox#Reports).

To contribute directly to reports, please submit patches via Gerrit to
this repository. If you'd like to request additional reports (or
changes to existing ones), please submit a Phabricator task to the
[Operations Software board](https://phabricator.wikimedia.org/tag/operations-software-development/).

# Custom Scripts #

All customscripts are contained in `customscripts/`.

# DNS Generator #

The DNS generation framework is contained in `dns/`.
