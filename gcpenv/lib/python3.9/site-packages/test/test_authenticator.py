# coding=utf-8
# pylint: disable=missing-docstring

from requests import Request
from ibm_cloud_sdk_core.authenticators import Authenticator


class TestAuthenticator(Authenticator):
    """A test of the Authenticator base class"""

    def validate(self) -> None:
        """Simulated validate() method."""

    def authenticate(self, req: Request) -> None:
        """Simulated authenticate() method."""


def test_authenticator():
    authenticator = TestAuthenticator()
    assert authenticator is not None
    assert authenticator.authentication_type() == Authenticator.AUTHTYPE_UNKNOWN
