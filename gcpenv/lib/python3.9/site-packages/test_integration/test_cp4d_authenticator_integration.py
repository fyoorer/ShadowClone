# pylint: disable=missing-docstring
import os

from ibm_cloud_sdk_core import get_authenticator_from_environment

# Note: Only the unit tests are run by default.
#
# In order to test with a live CP4D server, rename "ibm-credentials-cp4dtest.env.example" to
# "ibm-credentials-cp4dtest.env" in the resources folder and populate the fields.
# Then run this command:
# pytest test_integration/test_cp4d_authenticator_integration.py

IBM_CREDENTIALS_FILE = '../resources/ibm-credentials-cp4dtest.env'


def test_cp4d_authenticator_password():
    file_path = os.path.join(os.path.dirname(__file__), IBM_CREDENTIALS_FILE)
    os.environ['IBM_CREDENTIALS_FILE'] = file_path

    authenticator = get_authenticator_from_environment('cp4d_password_test')
    assert authenticator is not None
    assert authenticator.token_manager.password is not None
    assert authenticator.token_manager.apikey is None

    request = {'headers': {}}
    authenticator.authenticate(request)
    assert request['headers']['Authorization'] is not None
    assert 'Bearer' in request['headers']['Authorization']


def test_cp4d_authenticator_apikey():
    file_path = os.path.join(os.path.dirname(__file__), IBM_CREDENTIALS_FILE)
    os.environ['IBM_CREDENTIALS_FILE'] = file_path

    authenticator = get_authenticator_from_environment('cp4d_apikey_test')
    assert authenticator is not None
    assert authenticator.token_manager.password is None
    assert authenticator.token_manager.apikey is not None

    request = {'headers': {}}
    authenticator.authenticate(request)
    assert request['headers']['Authorization'] is not None
    assert 'Bearer' in request['headers']['Authorization']
