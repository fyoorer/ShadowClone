# pylint: disable=missing-docstring
import json

import jwt
import pytest
import responses

from ibm_cloud_sdk_core.authenticators import CloudPakForDataAuthenticator, Authenticator


def test_cp4d_authenticator():
    authenticator = CloudPakForDataAuthenticator('my_username', 'my_password', 'http://my_url')
    assert authenticator is not None
    assert authenticator.authentication_type() == Authenticator.AUTHTYPE_CP4D
    assert authenticator.token_manager.url == 'http://my_url/v1/authorize'
    assert authenticator.token_manager.username == 'my_username'
    assert authenticator.token_manager.password == 'my_password'
    assert authenticator.token_manager.disable_ssl_verification is False
    assert authenticator.token_manager.headers == {'Content-Type': 'application/json'}
    assert authenticator.token_manager.proxies is None

    authenticator.set_disable_ssl_verification(True)
    assert authenticator.token_manager.disable_ssl_verification is True

    with pytest.raises(TypeError) as err:
        authenticator.set_headers('dummy')
    assert str(err.value) == 'headers must be a dictionary'

    authenticator.set_headers({'dummy': 'headers'})
    assert authenticator.token_manager.headers == {'dummy': 'headers'}

    with pytest.raises(TypeError) as err:
        authenticator.set_proxies('dummy')
    assert str(err.value) == 'proxies must be a dictionary'

    authenticator.set_proxies({'dummy': 'proxies'})
    assert authenticator.token_manager.proxies == {'dummy': 'proxies'}


def test_disable_ssl_verification():
    authenticator = CloudPakForDataAuthenticator(
        'my_username', 'my_password', 'http://my_url', disable_ssl_verification=True
    )
    assert authenticator.token_manager.disable_ssl_verification is True

    authenticator.set_disable_ssl_verification(False)
    assert authenticator.token_manager.disable_ssl_verification is False


def test_invalid_disable_ssl_verification_type():
    with pytest.raises(TypeError) as err:
        authenticator = CloudPakForDataAuthenticator(
            'my_username', 'my_password', 'http://my_url', disable_ssl_verification='True'
        )
    assert str(err.value) == 'disable_ssl_verification must be a bool'

    authenticator = CloudPakForDataAuthenticator('my_username', 'my_password', 'http://my_url')
    assert authenticator.token_manager.disable_ssl_verification is False

    with pytest.raises(TypeError) as err:
        authenticator.set_disable_ssl_verification('True')
    assert str(err.value) == 'status must be a bool'


def test_cp4d_authenticator_validate_failed():
    with pytest.raises(ValueError) as err:
        CloudPakForDataAuthenticator('my_username', None, 'my_url')
    assert str(err.value) == 'Exactly one of `apikey` or `password` must be specified.'

    with pytest.raises(ValueError) as err:
        CloudPakForDataAuthenticator(username='my_username', url='my_url')
    assert str(err.value) == 'Exactly one of `apikey` or `password` must be specified.'

    with pytest.raises(ValueError) as err:
        CloudPakForDataAuthenticator('my_username', None, 'my_url', apikey=None)
    assert str(err.value) == 'Exactly one of `apikey` or `password` must be specified.'

    with pytest.raises(ValueError) as err:
        CloudPakForDataAuthenticator(None, 'my_password', 'my_url')
    assert str(err.value) == 'The username shouldn\'t be None.'

    with pytest.raises(ValueError) as err:
        CloudPakForDataAuthenticator(password='my_password', url='my_url')
    assert str(err.value) == 'The username shouldn\'t be None.'

    with pytest.raises(ValueError) as err:
        CloudPakForDataAuthenticator('my_username', 'my_password', None)
    assert str(err.value) == 'The url shouldn\'t be None.'

    with pytest.raises(ValueError) as err:
        CloudPakForDataAuthenticator(username='my_username', password='my_password')
    assert str(err.value) == 'The url shouldn\'t be None.'

    with pytest.raises(ValueError) as err:
        CloudPakForDataAuthenticator('{my_username}', 'my_password', 'my_url')
    assert (
        str(err.value) == 'The username and password shouldn\'t start or end with curly brackets or quotes. '
        'Please remove any surrounding {, }, or \" characters.'
    )

    with pytest.raises(ValueError) as err:
        CloudPakForDataAuthenticator('my_username', '{my_password}', 'my_url')
    assert (
        str(err.value) == 'The username and password shouldn\'t start or end with curly brackets or quotes. '
        'Please remove any surrounding {, }, or \" characters.'
    )

    with pytest.raises(ValueError) as err:
        CloudPakForDataAuthenticator('my_username', 'my_password', '{my_url}')
    assert (
        str(err.value) == 'The url shouldn\'t start or end with curly brackets or quotes. '
        'Please remove any surrounding {, }, or \" characters.'
    )


@responses.activate
def test_get_token():
    url = "https://test"
    access_token_layout = {
        "username": "dummy",
        "role": "Admin",
        "permissions": ["administrator", "manage_catalog"],
        "sub": "admin",
        "iss": "sss",
        "aud": "sss",
        "uid": "sss",
        "iat": 1559324664,
        "exp": 1559324664,
    }

    access_token = jwt.encode(
        access_token_layout, 'secret', algorithm='HS256', headers={'kid': '230498151c214b788dd97f22b85410a5'}
    )
    response = {
        "token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "expiration": 1524167011,
        "refresh_token": "jy4gl91BQ",
    }
    responses.add(responses.POST, url + '/v1/authorize', body=json.dumps(response), status=200)

    auth_headers = {'Host': 'cp4d.cloud.ibm.com:443'}
    authenticator = CloudPakForDataAuthenticator(
        'my_username', 'my_password', url + '/v1/authorize', headers=auth_headers
    )

    # Simulate an SDK API request that needs to be authenticated.
    request = {'headers': {}}

    # Trigger the "get token" processing to obtain the access token and add to the "SDK request".
    authenticator.authenticate(request)

    # Verify that the "authenticate()" method added the Authorization header
    assert request['headers']['Authorization'] is not None

    # Verify that the "get token" call contained the Host header.
    assert responses.calls[0].request.headers.get('Host') == 'cp4d.cloud.ibm.com:443'

    # Ensure '/v1/authorize' is added to the url if omitted
    authenticator = CloudPakForDataAuthenticator('my_username', 'my_password', url)

    request = {'headers': {}}
    authenticator.authenticate(request)
    assert request['headers']['Authorization'] is not None
