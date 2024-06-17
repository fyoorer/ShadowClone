# pylint: disable=missing-docstring

from ibm_cloud_sdk_core.authenticators import NoAuthAuthenticator, Authenticator


def test_no_auth_authenticator():
    authenticator = NoAuthAuthenticator()
    assert authenticator is not None
    assert authenticator.authentication_type() == Authenticator.AUTHTYPE_NOAUTH

    authenticator.validate()

    request = {'headers': {}}
    authenticator.authenticate(request)
    assert not request['headers']
