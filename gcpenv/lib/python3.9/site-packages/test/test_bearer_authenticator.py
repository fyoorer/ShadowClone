# pylint: disable=missing-docstring
import pytest

from ibm_cloud_sdk_core.authenticators import BearerTokenAuthenticator, Authenticator


def test_bearer_authenticator():
    authenticator = BearerTokenAuthenticator('my_bearer_token')
    assert authenticator is not None
    assert authenticator.authentication_type() == Authenticator.AUTHTYPE_BEARERTOKEN
    assert authenticator.bearer_token == 'my_bearer_token'

    authenticator.set_bearer_token('james bond')
    assert authenticator.bearer_token == 'james bond'

    request = {'headers': {}}
    authenticator.authenticate(request)
    assert request['headers']['Authorization'] == 'Bearer james bond'


def test_bearer_validate_failed():
    with pytest.raises(ValueError) as err:
        BearerTokenAuthenticator(None)
    assert str(err.value) == 'The bearer token shouldn\'t be None.'
    authenticator = BearerTokenAuthenticator('my_bearer_token')
    with pytest.raises(ValueError) as err:
        authenticator.set_bearer_token(None)
    assert str(err.value) == 'The bearer token shouldn\'t be None.'
