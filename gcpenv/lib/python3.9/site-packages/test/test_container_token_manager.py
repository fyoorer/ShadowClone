# pylint: disable=missing-docstring
import json
import os
import time
from urllib.parse import parse_qs

import responses
import pytest

from ibm_cloud_sdk_core import ApiException, ContainerTokenManager
from ibm_cloud_sdk_core.authenticators import ContainerAuthenticator

# pylint: disable=line-too-long
TEST_ACCESS_TOKEN_1 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImhlbGxvIiwicm9sZSI6InVzZXIiLCJwZXJtaXNzaW9ucyI6WyJhZG1pbmlzdHJhdG9yIiwiZGVwbG95bWVudF9hZG1pbiJdLCJzdWIiOiJoZWxsbyIsImlzcyI6IkpvaG4iLCJhdWQiOiJEU1giLCJ1aWQiOiI5OTkiLCJpYXQiOjE1NjAyNzcwNTEsImV4cCI6MTU2MDI4MTgxOSwianRpIjoiMDRkMjBiMjUtZWUyZC00MDBmLTg2MjMtOGNkODA3MGI1NDY4In0.cIodB4I6CCcX8vfIImz7Cytux3GpWyObt9Gkur5g1QI'
TEST_ACCESS_TOKEN_2 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IjIzMDQ5ODE1MWMyMTRiNzg4ZGQ5N2YyMmI4NTQxMGE1In0.eyJ1c2VybmFtZSI6ImR1bW15Iiwicm9sZSI6IkFkbWluIiwicGVybWlzc2lvbnMiOlsiYWRtaW5pc3RyYXRvciIsIm1hbmFnZV9jYXRhbG9nIl0sInN1YiI6ImFkbWluIiwiaXNzIjoic3NzIiwiYXVkIjoic3NzIiwidWlkIjoic3NzIiwiaWF0IjozNjAwLCJleHAiOjE2MjgwMDcwODF9.zvUDpgqWIWs7S1CuKv40ERw1IZ5FqSFqQXsrwZJyfRM'
TEST_REFRESH_TOKEN = 'Xj7Gle500MachEOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImhlbGxvIiwicm9sZSI6InVzZXIiLCJwZXJtaXNzaW9ucyI6WyJhZG1pbmlzdHJhdG9yIiwiZGVwbG95bWVudF9hZG1pbiJdLCJzdWIiOiJoZWxsbyIsImlzcyI6IkpvaG4iLCJhdWQiOiJEU1giLCJ1aWQiOiI5OTkiLCJpYXQiOjE1NjAyNzcwNTEsImV4cCI6MTU2MDI4MTgxOSwianRpIjoiMDRkMjBiMjUtZWUyZC00MDBmLTg2MjMtOGNkODA3MGI1NDY4In0.cIodB4I6CCcX8vfIImz7Cytux3GpWyObt9Gkur5g1QI'
MOCK_IAM_PROFILE_NAME = 'iam-user-123'
MOCK_CLIENT_ID = 'client-id-1'
MOCK_CLIENT_SECRET = 'client-secret-1'

cr_token_file = os.path.join(os.path.dirname(__file__), '../resources/cr-token.txt')


def _get_current_time() -> int:
    return int(time.time())


def mock_iam_response(func):
    """This is decorator function which extends `responses.activate`.
    This sets up all the mock response stuffs.
    """

    def callback(request):
        assert request.headers['Accept'] == 'application/json'
        assert request.headers['Content-Type'] == 'application/x-www-form-urlencoded'

        payload = parse_qs(request.body)

        assert payload['cr_token'][0] == 'cr-token-1'
        assert payload['grant_type'][0] == 'urn:ibm:params:oauth:grant-type:cr-token'
        assert payload.get('profile_name', [None])[0] or payload.get('profile_id', [None])[0]

        status_code = 200

        scope = payload.get('scope')[0] if payload.get('scope') else None
        if scope == 'send-second-token':
            access_token = TEST_ACCESS_TOKEN_2
        elif scope == 'status-bad-request':
            access_token = None
            status_code = 400
        elif scope == 'check-basic-auth':
            assert request.headers['Authorization'] == 'Basic Y2xpZW50LWlkLTE6Y2xpZW50LXNlY3JldC0x'
            access_token = TEST_ACCESS_TOKEN_1
        else:
            access_token = TEST_ACCESS_TOKEN_1

        response = json.dumps(
            {
                'access_token': access_token,
                'token_type': 'Bearer',
                'expires_in': 3600,
                'expiration': _get_current_time() + 3600,
                'refresh_token': TEST_REFRESH_TOKEN,
            }
        )

        return (status_code, {}, response)

    @responses.activate
    def wrapper():
        response = responses.CallbackResponse(
            method=responses.POST,
            url='https://iam.cloud.ibm.com/identity/token',
            callback=callback,
        )

        responses.add(response)

        func()

    return wrapper


@mock_iam_response
def test_request_token_auth_default():
    iam_url = "https://iam.cloud.ibm.com/identity/token"

    token_manager = ContainerTokenManager(
        cr_token_filename=cr_token_file,
        iam_profile_name=MOCK_IAM_PROFILE_NAME,
    )
    token_manager.request_token()

    assert len(responses.calls) == 1
    assert responses.calls[0].request.url == iam_url
    assert responses.calls[0].request.headers.get('Authorization') is None
    assert json.loads(responses.calls[0].response.text)['access_token'] == TEST_ACCESS_TOKEN_1


@mock_iam_response
def test_request_token_auth_in_ctor():
    default_auth_header = 'Basic Yng6Yng='
    token_manager = ContainerTokenManager(
        cr_token_filename=cr_token_file, iam_profile_name=MOCK_IAM_PROFILE_NAME, client_id='foo', client_secret='bar'
    )

    token_manager.request_token()

    assert len(responses.calls) == 1
    assert responses.calls[0].request.headers['Authorization'] != default_auth_header
    assert json.loads(responses.calls[0].response.text)['access_token'] == TEST_ACCESS_TOKEN_1
    assert 'scope' not in responses.calls[0].response.request.body


@mock_iam_response
def test_request_token_auth_in_ctor_with_scope():
    default_auth_header = 'Basic Yng6Yng='
    token_manager = ContainerTokenManager(
        cr_token_filename=cr_token_file,
        iam_profile_name=MOCK_IAM_PROFILE_NAME,
        client_id='foo',
        client_secret='bar',
        scope='john snow',
    )

    token_manager.request_token()

    assert len(responses.calls) == 1
    assert responses.calls[0].request.headers['Authorization'] != default_auth_header
    assert json.loads(responses.calls[0].response.text)['access_token'] == TEST_ACCESS_TOKEN_1
    assert 'scope=john+snow' in responses.calls[0].response.request.body


def test_retrieve_cr_token_success():
    token_manager = ContainerTokenManager(
        cr_token_filename=cr_token_file,
    )

    cr_token = token_manager.retrieve_cr_token()

    assert cr_token == 'cr-token-1'


def test_retrieve_cr_token_fail():
    token_manager = ContainerTokenManager(
        cr_token_filename='bogus-cr-token-file',
    )

    with pytest.raises(Exception) as err:
        token_manager.retrieve_cr_token()

    assert (
        str(err.value)
        == 'Unable to retrieve the CR token: Error reading CR token from file bogus-cr-token-file: [Errno 2] No such file or directory: \'bogus-cr-token-file\''
    )


@mock_iam_response
def test_get_token_success():
    token_manager = ContainerTokenManager(
        cr_token_filename=cr_token_file,
        iam_profile_name=MOCK_IAM_PROFILE_NAME,
    )

    access_token = token_manager.access_token
    assert access_token is None

    access_token = token_manager.get_token()
    assert access_token == TEST_ACCESS_TOKEN_1
    assert token_manager.access_token == TEST_ACCESS_TOKEN_1

    # Verify the token manager return the cached value.
    # Before we call the `get_token` again, set the expiration and time.
    # This is necessary because we are using a fix JWT response.
    token_manager.expire_time = _get_current_time() + 3600
    token_manager.refresh_time = _get_current_time() + 3600
    token_manager.set_scope('send-second-token')
    access_token = token_manager.get_token()
    assert access_token == TEST_ACCESS_TOKEN_1
    assert token_manager.access_token == TEST_ACCESS_TOKEN_1

    # Force expiration to get the second token.
    token_manager.expire_time = _get_current_time() - 1
    access_token = token_manager.get_token()
    assert access_token == TEST_ACCESS_TOKEN_2
    assert token_manager.access_token == TEST_ACCESS_TOKEN_2


@mock_iam_response
def test_request_token_success():
    token_manager = ContainerTokenManager(
        cr_token_filename=cr_token_file,
        iam_profile_name=MOCK_IAM_PROFILE_NAME,
    )

    token_response = token_manager.request_token()
    assert token_response['access_token'] == TEST_ACCESS_TOKEN_1


@mock_iam_response
def test_authenticate_success():
    authenticator = ContainerAuthenticator(cr_token_filename=cr_token_file, iam_profile_name=MOCK_IAM_PROFILE_NAME)

    request = {'headers': {}}

    authenticator.authenticate(request)
    assert request['headers']['Authorization'] == 'Bearer ' + TEST_ACCESS_TOKEN_1

    # Verify the token manager return the cached value.
    # Before we call the `get_token` again, set the expiration and time.
    # This is necessary because we are using a fix JWT response.
    authenticator.token_manager.expire_time = _get_current_time() + 3600
    authenticator.token_manager.refresh_time = _get_current_time() + 3600
    authenticator.token_manager.set_scope('send-second-token')
    authenticator.authenticate(request)
    assert request['headers']['Authorization'] == 'Bearer ' + TEST_ACCESS_TOKEN_1

    # Force expiration to get the second token.
    authenticator.token_manager.expire_time = _get_current_time() - 1
    authenticator.authenticate(request)
    assert request['headers']['Authorization'] == 'Bearer ' + TEST_ACCESS_TOKEN_2


@mock_iam_response
def test_authenticate_fail_no_cr_token():
    authenticator = ContainerAuthenticator(
        cr_token_filename='bogus-cr-token-file',
        iam_profile_name=MOCK_IAM_PROFILE_NAME,
        url='https://bogus.iam.endpoint',
    )

    request = {'headers': {}}

    with pytest.raises(Exception) as err:
        authenticator.authenticate(request)

    assert (
        str(err.value)
        == 'Unable to retrieve the CR token: Error reading CR token from file bogus-cr-token-file: [Errno 2] No such file or directory: \'bogus-cr-token-file\''
    )


@mock_iam_response
def test_authenticate_fail_iam():
    authenticator = ContainerAuthenticator(
        cr_token_filename=cr_token_file, iam_profile_name=MOCK_IAM_PROFILE_NAME, scope='status-bad-request'
    )

    request = {'headers': {}}

    with pytest.raises(ApiException) as err:
        authenticator.authenticate(request)

    assert str(err.value) == 'Error: Bad Request, Code: 400'


@mock_iam_response
def test_client_id_and_secret():
    token_manager = ContainerTokenManager(
        cr_token_filename=cr_token_file,
        iam_profile_name=MOCK_IAM_PROFILE_NAME,
    )

    token_manager.set_client_id_and_secret(MOCK_CLIENT_ID, MOCK_CLIENT_SECRET)
    token_manager.set_scope('check-basic-auth')
    access_token = token_manager.get_token()
    assert access_token == TEST_ACCESS_TOKEN_1


@mock_iam_response
def test_setter_methods():
    token_manager = ContainerTokenManager(
        cr_token_filename='bogus-cr-token-file',
        iam_profile_name=MOCK_IAM_PROFILE_NAME,
    )

    assert token_manager.iam_profile_id is None
    assert token_manager.iam_profile_name == MOCK_IAM_PROFILE_NAME
    assert token_manager.cr_token_filename == 'bogus-cr-token-file'

    token_manager.set_iam_profile_id('iam-id-123')
    token_manager.set_iam_profile_name(None)
    token_manager.set_cr_token_filename(cr_token_file)

    assert token_manager.iam_profile_id == 'iam-id-123'
    assert token_manager.iam_profile_name is None
    assert token_manager.cr_token_filename == cr_token_file

    access_token = token_manager.get_token()
    assert access_token == TEST_ACCESS_TOKEN_1
