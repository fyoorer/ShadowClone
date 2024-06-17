# pylint: disable=missing-docstring
import pytest

from ibm_cloud_sdk_core.authenticators import BasicAuthenticator, Authenticator


def test_basic_authenticator():
    authenticator = BasicAuthenticator('my_username', 'my_password')
    assert authenticator is not None
    assert authenticator.authentication_type() == Authenticator.AUTHTYPE_BASIC
    assert authenticator.username == 'my_username'
    assert authenticator.password == 'my_password'

    request = {'headers': {}}
    authenticator.authenticate(request)
    assert request['headers']['Authorization'] == 'Basic bXlfdXNlcm5hbWU6bXlfcGFzc3dvcmQ='


def test_basic_authenticator_validate_failed():
    with pytest.raises(ValueError) as err:
        BasicAuthenticator('my_username', None)
    assert str(err.value) == 'The username and password shouldn\'t be None.'

    with pytest.raises(ValueError) as err:
        BasicAuthenticator(None, 'my_password')
    assert str(err.value) == 'The username and password shouldn\'t be None.'

    with pytest.raises(ValueError) as err:
        BasicAuthenticator('{my_username}', 'my_password')
    assert (
        str(err.value) == 'The username and password shouldn\'t start or end with curly brackets or quotes. '
        'Please remove any surrounding {, }, or \" characters.'
    )

    with pytest.raises(ValueError) as err:
        BasicAuthenticator('my_username', '{my_password}')
    assert (
        str(err.value) == 'The username and password shouldn\'t start or end with curly brackets or quotes. '
        'Please remove any surrounding {, }, or \" characters.'
    )
