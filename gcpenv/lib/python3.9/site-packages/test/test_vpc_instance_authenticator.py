# pylint: disable=missing-docstring
import pytest

from ibm_cloud_sdk_core.authenticators import VPCInstanceAuthenticator, Authenticator


TEST_IAM_PROFILE_CRN = 'crn:iam-profile:123'
TEST_IAM_PROFILE_ID = 'iam-id-123'


def test_constructor():
    authenticator = VPCInstanceAuthenticator(iam_profile_id=TEST_IAM_PROFILE_ID, url='someurl.com')
    assert authenticator is not None
    assert authenticator.authentication_type() == Authenticator.AUTHTYPE_VPC
    assert authenticator.token_manager.iam_profile_crn is None
    assert authenticator.token_manager.iam_profile_id == TEST_IAM_PROFILE_ID
    assert authenticator.token_manager.url == 'someurl.com'


def test_setters():
    authenticator = VPCInstanceAuthenticator(iam_profile_id=TEST_IAM_PROFILE_ID, url='someurl.com')
    assert authenticator is not None
    assert authenticator.authentication_type() == Authenticator.AUTHTYPE_VPC
    assert authenticator.token_manager.iam_profile_crn is None
    assert authenticator.token_manager.iam_profile_id == TEST_IAM_PROFILE_ID
    assert authenticator.token_manager.url == 'someurl.com'

    # Set the IAM profile CRN to trigger a validation which will fail,
    # because at most one of iam_profile_crn or iam_profile_id may be specified.
    with pytest.raises(ValueError) as err:
        authenticator.set_iam_profile_crn(TEST_IAM_PROFILE_CRN)
    assert str(err.value) == 'At most one of "iam_profile_id" or "iam_profile_crn" may be specified.'

    authenticator.set_iam_profile_id(None)
    assert authenticator.token_manager.iam_profile_id is None

    authenticator.set_iam_profile_crn(TEST_IAM_PROFILE_CRN)
    assert authenticator.token_manager.iam_profile_crn == TEST_IAM_PROFILE_CRN


def test_constructor_validate_failed():
    with pytest.raises(ValueError) as err:
        VPCInstanceAuthenticator(
            iam_profile_crn=TEST_IAM_PROFILE_CRN,
            iam_profile_id=TEST_IAM_PROFILE_ID,
        )
    assert str(err.value) == 'At most one of "iam_profile_id" or "iam_profile_crn" may be specified.'


def test_authenticate():
    def mock_get_token():
        return 'mock_token'

    authenticator = VPCInstanceAuthenticator(iam_profile_crn=TEST_IAM_PROFILE_CRN)
    authenticator.token_manager.get_token = mock_get_token

    # Simulate an SDK API request that needs to be authenticated.
    request = {'headers': {}}

    # Trigger the "get token" processing to obtain the access token and add to the "SDK request".
    authenticator.authenticate(request)

    # Verify that the "authenticate()" method added the Authorization header
    assert request['headers']['Authorization'] == 'Bearer mock_token'
