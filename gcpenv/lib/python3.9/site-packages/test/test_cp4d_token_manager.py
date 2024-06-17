# pylint: disable=missing-docstring
import json
import time

import jwt
import responses

from ibm_cloud_sdk_core import CP4DTokenManager


@responses.activate
def test_request_token():
    url = "https://test"
    now = time.time()
    access_token_layout = {
        "username": "dummy",
        "role": "Admin",
        "permissions": ["administrator", "manage_catalog"],
        "sub": "admin",
        "iss": "sss",
        "aud": "sss",
        "uid": "sss",
        "iat": now,
        "exp": now + 3600,
    }

    access_token = jwt.encode(
        access_token_layout, 'secret', algorithm='HS256', headers={'kid': '230498151c214b788dd97f22b85410a5'}
    )
    response = {
        "token": access_token,
    }
    responses.add(responses.POST, url + '/v1/authorize', body=json.dumps(response), status=200)

    token_manager = CP4DTokenManager("username", "password", url)
    token_manager.set_disable_ssl_verification(True)
    token = token_manager.get_token()

    assert len(responses.calls) == 1
    assert responses.calls[0].request.url == url + '/v1/authorize'
    assert token == access_token

    token_manager = CP4DTokenManager("username", "password", url + '/v1/authorize')
    token = token_manager.get_token()
    assert len(responses.calls) == 2
    assert responses.calls[1].request.url == url + '/v1/authorize'
    assert token == access_token

    token_manager = CP4DTokenManager(username="username", apikey="fake_api_key", url=url + '/v1/authorize')
    token = token_manager.get_token()
    assert len(responses.calls) == 3
    assert responses.calls[2].request.url == url + '/v1/authorize'
    assert token == access_token
