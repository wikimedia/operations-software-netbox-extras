#!/usr/bin/env python3
#
# Export specified CustomScript outputs via web.
#
import requests

from functools import lru_cache
from configparser import ConfigParser

from flask import Flask, abort, make_response

application = app = Flask(__name__)  # flake8: disable=invalid-name

ALLOWED_SCRIPTS = ('getstats.GetDeviceStats',)


@lru_cache(maxsize=None)
def config():
    config = ConfigParser()
    config.read("/etc/netbox/scripts.cfg")
    return config


@app.route('/<script>')
def run_script(script):
    # Only support specific scripts
    if script not in ALLOWED_SCRIPTS:
        abort(404)

    # construct request
    api_url = '{}api/extras/scripts/{}/'.format(config()['netbox']['api'], script)
    headers = {'Authorization': 'Token {}'.format(config()['netbox']['token_rw'])}
    data = {"data": {}, "commit": 1}
    result = requests.post(api_url, headers=headers, json=data)

    # if the request didn't work, return error
    if not result.ok:
        return make_response(result.text, result.status_code)

    # Return the resulting output of the script
    return result.json()['output']
