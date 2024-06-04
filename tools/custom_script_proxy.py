#!/usr/bin/env python3
#
# Export specified CustomScript outputs via web.
#
import time

from functools import lru_cache

from configparser import ConfigParser

import requests

from flask import Flask, abort, make_response

application = app = Flask(__name__)  # noqa: invalid-name,unused-variable

ALLOWED_SCRIPTS = ("getstats.GetDeviceStats", "hiera_export.HieraExport")
TIMEOUT = 300


@lru_cache(maxsize=None)
def config():
    """Return the the content of the config file."""
    configp = ConfigParser()
    configp.read("/etc/netbox/scripts.cfg")
    return configp


def get_result(result_url, headers):
    """Accept a 'result' URL and busy wait until timeout for results"""
    start = time.time()
    while time.time() < start + TIMEOUT:
        time.sleep(0.2)
        result = requests.get(result_url, headers=headers, timeout=60)
        if not result.ok:
            return make_response(result.text, result.status_code)
        data = result.json()
        if data["data"] is not None:
            return data["data"]["output"]
    return make_response("Timeout exceeded.", 500)


@app.route("/<script>")  # noqa: unused-function
def run_script(script):
    """Script entry point."""
    # Only support specific scripts
    if script not in ALLOWED_SCRIPTS:
        abort(404)

    # construct request
    api_url = f"{config()['netbox']['api']}api/extras/scripts/{script}/"
    headers = {"Authorization": f"Token {config()['netbox']['token_rw']}"}
    data = {"data": {}, "commit": 1}
    result = requests.post(api_url, headers=headers, json=data, timeout=60)

    # if the request didn't work, return error
    if not result.ok:
        return make_response(result.text, result.status_code)

    # Return the resulting output of the script
    return get_result(result.json()["result"]["url"], headers)
