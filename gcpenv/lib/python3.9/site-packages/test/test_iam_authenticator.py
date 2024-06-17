# pylint: disable=missing-docstring
import json

import jwt
import pytest
import responses

from ibm_cloud_sdk_core.authenticators import IAMAuthenticator, Authenticator


def test_iam_authenticator():
    authenticator = IAMAuthenticator(apikey='my_apikey')
    assert authenticator is not None
    assert authenticator.authentication_type() == Authenticator.AUTHTYPE_IAM
    assert authenticator.token_manager.url == 'https://iam.cloud.ibm.com'
    assert authenticator.token_manager.client_id is None
    assert authenticator.token_manager.client_secret is None
    assert authenticator.token_manager.disable_ssl_verification is False
    assert authenticator.token_manager.headers is None
    assert authenticator.token_manager.proxies is None
    assert authenticator.token_manager.apikey == 'my_apikey'
    assert authenticator.token_manager.scope is None

    authenticator.set_client_id_and_secret('tom', 'jerry')
    assert authenticator.token_manager.client_id == 'tom'
    assert authenticator.token_manager.client_secret == 'jerry'

    authenticator.set_scope('scope1 scope2 scope3')
    assert authenticator.token_manager.scope == 'scope1 scope2 scope3'

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

    authenticator.set_disable_ssl_verification(True)
    assert authenticator.token_manager.disable_ssl_verification


def test_disable_ssl_verification():
    authenticator = IAMAuthenticator(apikey='my_apikey', disable_ssl_verification=True)
    assert authenticator.token_manager.disable_ssl_verification is True

    authenticator.set_disable_ssl_verification(False)
    assert authenticator.token_manager.disable_ssl_verification is False


def test_invalid_disable_ssl_verification_type():
    with pytest.raises(TypeError) as err:
        authenticator = IAMAuthenticator(apikey='my_apikey', disable_ssl_verification='True')
    assert str(err.value) == 'disable_ssl_verification must be a bool'

    authenticator = IAMAuthenticator(apikey='my_apikey')
    assert authenticator.token_manager.disable_ssl_verification is False

    with pytest.raises(TypeError) as err:
        authenticator.set_disable_ssl_verification('True')
    assert str(err.value) == 'status must be a bool'


def test_iam_authenticator_with_scope():
    authenticator = IAMAuthenticator(apikey='my_apikey', scope='scope1 scope2')
    assert authenticator is not None
    assert authenticator.token_manager.scope == 'scope1 scope2'


def test_iam_authenticator_validate_failed():
    with pytest.raises(ValueError) as err:
        IAMAuthenticator(None)
    assert str(err.value) == 'The apikey shouldn\'t be None.'

    with pytest.raises(ValueError) as err:
        IAMAuthenticator('{apikey}')
    assert (
        str(err.value) == 'The apikey shouldn\'t start or end with curly brackets or quotes. '
        'Please remove any surrounding {, }, or \" characters.'
    )

    with pytest.raises(ValueError) as err:
        IAMAuthenticator('my_apikey', client_id='my_client_id')
    assert str(err.value) == 'Both client_id and client_secret should be initialized.'

    with pytest.raises(ValueError) as err:
        IAMAuthenticator('my_apikey', client_secret='my_client_secret')
    assert str(err.value) == 'Both client_id and client_secret should be initialized.'


@responses.activate
def test_get_token():
    url = "https://iam.cloud.ibm.com/identity/token"
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
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "expiration": 1524167011,
        "refresh_token": "jy4gl91BQ",
    }
    responses.add(responses.POST, url=url, body=json.dumps(response), status=200)

    auth_headers = {'Host': 'iam.cloud.ibm.com:443'}
    authenticator = IAMAuthenticator('my_apikey', headers=auth_headers)

    # Simulate an SDK API request that needs to be authenticated.
    request = {'headers': {}}

    # Trigger the "get token" processing to obtain the access token and add to the "SDK request".
    authenticator.authenticate(request)

    # Verify that the "authenticate()" method added the Authorization header
    assert request['headers']['Authorization'] is not None

    # Verify that the "get token" call contained the Host header.
    assert responses.calls[0].request.headers.get('Host') == 'iam.cloud.ibm.com:443'


def test_multiple_iam_authenticators():
    authenticator_1 = IAMAuthenticator('my_apikey')
    assert authenticator_1.token_manager.request_payload['apikey'] == 'my_apikey'

    authenticator_2 = IAMAuthenticator('my_other_apikey')
    assert authenticator_2.token_manager.request_payload['apikey'] == 'my_other_apikey'

    assert authenticator_1.token_manager.request_payload['apikey'] == 'my_apikey'
