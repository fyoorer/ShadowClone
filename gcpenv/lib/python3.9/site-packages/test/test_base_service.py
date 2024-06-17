# coding=utf-8
# pylint: disable=missing-docstring,protected-access,too-few-public-methods
import gzip
import json
import os
import ssl
import tempfile
import time
from shutil import copyfile
from typing import Optional
from urllib3.exceptions import ConnectTimeoutError, MaxRetryError

import jwt
import pytest
import responses
import requests

from ibm_cloud_sdk_core import ApiException
from ibm_cloud_sdk_core import BaseService, DetailedResponse
from ibm_cloud_sdk_core import CP4DTokenManager
from ibm_cloud_sdk_core import get_authenticator_from_environment
from ibm_cloud_sdk_core.authenticators import (
    IAMAuthenticator,
    NoAuthAuthenticator,
    Authenticator,
    BasicAuthenticator,
    CloudPakForDataAuthenticator,
)


class IncludeExternalConfigService(BaseService):
    default_service_url = 'https://servicesthatincludeexternalconfig.com/api'

    def __init__(
        self, api_version: str, authenticator: Optional[Authenticator] = None, trace_id: Optional[str] = None
    ) -> None:
        BaseService.__init__(
            self, service_url=self.default_service_url, authenticator=authenticator, disable_ssl_verification=False
        )
        self.api_version = api_version
        self.trace_id = trace_id
        self.configure_service('include-external-config')


class AnyServiceV1(BaseService):
    default_url = 'https://gateway.watsonplatform.net/test/api'

    def __init__(
        self,
        version: str,
        service_url: str = default_url,
        authenticator: Optional[Authenticator] = None,
        disable_ssl_verification: bool = False,
    ) -> None:
        BaseService.__init__(
            self,
            service_url=service_url,
            authenticator=authenticator,
            disable_ssl_verification=disable_ssl_verification,
        )
        self.version = version

    def op_with_path_params(self, path0: str, path1: str) -> DetailedResponse:
        if path0 is None:
            raise ValueError('path0 must be provided')
        if path1 is None:
            raise ValueError('path1 must be provided')
        params = {'version': self.version}
        url = '/v1/foo/{0}/bar/{1}/baz'.format(*self._encode_path_vars(path0, path1))
        request = self.prepare_request(method='GET', url=url, params=params)
        response = self.send(request)
        return response

    def with_http_config(self, http_config: dict) -> DetailedResponse:
        self.set_http_config(http_config)
        request = self.prepare_request(method='GET', url='')
        response = self.send(request)
        return response

    def any_service_call(self) -> DetailedResponse:
        request = self.prepare_request(method='GET', url='')
        response = self.send(request)
        return response

    def head_request(self) -> DetailedResponse:
        request = self.prepare_request(method='HEAD', url='')
        response = self.send(request)
        return response

    def get_document_as_stream(self) -> DetailedResponse:
        params = {'version': self.version}
        url = '/v1/streamjson'
        request = self.prepare_request(method='GET', url=url, params=params)
        response = self.send(request, stream=True)
        return response


def get_access_token() -> str:
    access_token_layout = {
        "username": "dummy",
        "role": "Admin",
        "permissions": ["administrator", "manage_catalog"],
        "sub": "admin",
        "iss": "sss",
        "aud": "sss",
        "uid": "sss",
        "iat": 3600,
        "exp": int(time.time()),
    }

    access_token = jwt.encode(
        access_token_layout, 'secret', algorithm='HS256', headers={'kid': '230498151c214b788dd97f22b85410a5'}
    )
    return access_token


def test_invalid_authenticator():
    with pytest.raises(ValueError) as err:
        AnyServiceV1('2021-08-18')

    assert str(err.value) == 'authenticator must be provided'


@responses.activate
def test_url_encoding():
    service = AnyServiceV1('2017-07-07', authenticator=NoAuthAuthenticator())

    # All characters in path0 _must_ be encoded in path segments
    path0 = ' \"<>^`{}|/\\?#%[]'
    path0_encoded = '%20%22%3C%3E%5E%60%7B%7D%7C%2F%5C%3F%23%25%5B%5D'
    # All non-ASCII chars _must_ be encoded in path segments
    path1 = '比萨浇头'.encode('utf8')  # "pizza toppings"
    path1_encoded = '%E6%AF%94%E8%90%A8%E6%B5%87%E5%A4%B4'

    path_encoded = '/v1/foo/' + path0_encoded + '/bar/' + path1_encoded + '/baz'
    test_url = service.default_url + path_encoded

    responses.add(
        responses.GET, test_url, status=200, body=json.dumps({"foobar": "baz"}), content_type='application/json'
    )

    # Set Host as a default header on the service.
    service.set_default_headers({'Host': 'alternatehost.ibm.com:443'})

    response = service.op_with_path_params(path0, path1)

    assert response is not None
    assert len(responses.calls) == 1
    assert path_encoded in responses.calls[0].request.url
    assert 'version=2017-07-07' in responses.calls[0].request.url

    # Verify that the Host header was set in the request.
    assert responses.calls[0].request.headers.get('Host') == 'alternatehost.ibm.com:443'


@responses.activate
def test_stream_json_response():
    service = AnyServiceV1('2017-07-07', authenticator=NoAuthAuthenticator())

    path = '/v1/streamjson'
    test_url = service.default_url + path

    expected_response = json.dumps({"id": 1, "rev": "v1", "content": "this is a document"})

    # print("Expected response: ", expected_response)

    # Simulate a JSON response
    responses.add(responses.GET, test_url, status=200, body=expected_response, content_type='application/json')

    # Invoke the operation and receive an "iterable" as the response
    response = service.get_document_as_stream()

    assert response is not None
    assert len(responses.calls) == 1

    # retrieve the requests.Response object from the DetailedResponse
    resp = response.get_result()
    assert isinstance(resp, requests.Response)
    assert hasattr(resp, "iter_content")

    # Retrieve the response body, one chunk at a time.
    actual_response = ''
    for chunk in resp.iter_content(chunk_size=3):
        actual_response += chunk.decode("utf-8")

    # print("Actual response: ", actual_response)
    assert actual_response == expected_response


@responses.activate
def test_http_config():
    service = AnyServiceV1('2017-07-07', authenticator=NoAuthAuthenticator())
    responses.add(
        responses.GET,
        service.default_url,
        status=200,
        body=json.dumps({"foobar": "baz"}),
        content_type='application/json',
    )

    response = service.with_http_config({'timeout': 100})
    assert response is not None
    assert len(responses.calls) == 1


def test_fail_http_config():
    service = AnyServiceV1('2017-07-07', authenticator=NoAuthAuthenticator())
    with pytest.raises(TypeError):
        service.with_http_config(None)


@responses.activate
def test_cwd():
    file_path = os.path.join(os.path.dirname(__file__), '../resources/ibm-credentials.env')
    # Try changing working directories to test getting creds from cwd
    cwd = os.getcwd()
    os.chdir(os.path.dirname(file_path))
    iam_authenticator = get_authenticator_from_environment('ibm_watson')
    service = AnyServiceV1('2017-07-07', authenticator=iam_authenticator)
    service.configure_service('ibm_watson')
    os.chdir(cwd)
    assert service.service_url == 'https://cwdserviceurl'
    assert service.authenticator is not None

    # Copy credentials file to cwd to test loading from current working directory
    temp_env_path = os.getcwd() + '/ibm-credentials.env'
    copyfile(file_path, temp_env_path)
    iam_authenticator = get_authenticator_from_environment('ibm_watson')
    service = AnyServiceV1('2017-07-07', authenticator=iam_authenticator)
    service.configure_service('ibm_watson')
    os.remove(temp_env_path)
    assert service.service_url == 'https://cwdserviceurl'
    assert service.authenticator is not None


@responses.activate
def test_iam():
    file_path = os.path.join(os.path.dirname(__file__), '../resources/ibm-credentials-iam.env')
    os.environ['IBM_CREDENTIALS_FILE'] = file_path
    iam_authenticator = get_authenticator_from_environment('ibm-watson')
    service = AnyServiceV1('2017-07-07', authenticator=iam_authenticator)
    assert service.service_url == 'https://gateway.watsonplatform.net/test/api'
    del os.environ['IBM_CREDENTIALS_FILE']
    assert service.authenticator is not None

    response = {
        "access_token": get_access_token(),
        "token_type": "Bearer",
        "expires_in": 3600,
        "expiration": int(time.time()),
        "refresh_token": "jy4gl91BQ",
    }
    responses.add(responses.POST, url='https://iam.cloud.ibm.com/identity/token', body=json.dumps(response), status=200)
    responses.add(
        responses.GET,
        url='https://gateway.watsonplatform.net/test/api',
        body=json.dumps({"foobar": "baz"}),
        content_type='application/json',
    )
    service.any_service_call()
    assert "grant-type%3Aapikey" in responses.calls[0].request.body


def test_no_auth():
    class MadeUp:
        def __init__(self):
            self.lazy = 'made up'

    with pytest.raises(ValueError) as err:
        service = AnyServiceV1('2017-07-07', authenticator=MadeUp())
        service.prepare_request(
            responses.GET,
            url='https://gateway.watsonplatform.net/test/api',
        )
        assert str(err.value) == 'authenticator should be of type Authenticator'

    service = AnyServiceV1('2017-07-07', authenticator=NoAuthAuthenticator())
    service.prepare_request(
        responses.GET,
        url='https://gateway.watsonplatform.net/test/api',
    )
    assert service.authenticator is not None
    assert isinstance(service.authenticator, Authenticator)


def test_for_cp4d():
    cp4d_authenticator = CloudPakForDataAuthenticator('my_username', 'my_password', 'my_url')
    service = AnyServiceV1('2017-07-07', authenticator=cp4d_authenticator)
    assert service.authenticator.token_manager is not None
    assert service.authenticator.token_manager.username == 'my_username'
    assert service.authenticator.token_manager.password == 'my_password'
    assert service.authenticator.token_manager.url == 'my_url/v1/authorize'
    assert isinstance(service.authenticator.token_manager, CP4DTokenManager)


def test_disable_ssl_verification():
    service1 = AnyServiceV1('2017-07-07', authenticator=NoAuthAuthenticator(), disable_ssl_verification=True)
    assert service1.disable_ssl_verification is True

    service1.set_disable_ssl_verification(False)
    assert service1.disable_ssl_verification is False

    cp4d_authenticator = CloudPakForDataAuthenticator('my_username', 'my_password', 'my_url')
    service2 = AnyServiceV1('2017-07-07', authenticator=cp4d_authenticator)
    assert service2.disable_ssl_verification is False
    cp4d_authenticator.set_disable_ssl_verification(True)
    assert service2.authenticator.token_manager.disable_ssl_verification is True


@responses.activate
def test_http_head():
    service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
    expected_headers = {'Test-Header1': 'value1', 'Test-Header2': 'value2'}
    responses.add(responses.HEAD, service.default_url, status=200, headers=expected_headers, content_type=None)

    response = service.head_request()
    assert response is not None
    assert len(responses.calls) == 1
    assert response.headers is not None
    assert response.headers == expected_headers


@responses.activate
def test_response_with_no_body():
    service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
    responses.add(responses.GET, service.default_url, status=200, body=None)

    response = service.any_service_call()
    assert response is not None
    assert len(responses.calls) == 1
    assert response.get_result() is None


def test_has_bad_first_or_last_char():
    with pytest.raises(ValueError) as err:
        basic_authenticator = BasicAuthenticator('{my_username}', 'my_password')
        AnyServiceV1('2018-11-20', authenticator=basic_authenticator).prepare_request(
            responses.GET, 'https://gateway.watsonplatform.net/test/api'
        )
    assert (
        str(err.value) == 'The username and password shouldn\'t start or end with curly brackets or quotes. '
        'Please remove any surrounding {, }, or \" characters.'
    )


@responses.activate
def test_request_server_error():
    with pytest.raises(ApiException, match=r'internal server error') as err:
        responses.add(
            responses.GET,
            'https://gateway.watsonplatform.net/test/api',
            status=500,
            body=json.dumps({'error': 'internal server error'}),
            content_type='application/json',
        )
        service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
        prepped = service.prepare_request('GET', url='')
        service.send(prepped)
    assert err.value.code == 500
    assert err.value.http_response.headers['Content-Type'] == 'application/json'
    assert err.value.message == 'internal server error'


@responses.activate
def test_request_success_json():
    responses.add(
        responses.GET,
        'https://gateway.watsonplatform.net/test/api',
        status=200,
        body=json.dumps({'foo': 'bar'}),
        content_type='application/json',
    )
    service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
    prepped = service.prepare_request('GET', url='')
    detailed_response = service.send(prepped)
    assert detailed_response.get_result() == {'foo': 'bar'}

    service = AnyServiceV1('2018-11-20', authenticator=BasicAuthenticator('my_username', 'my_password'))
    service.set_default_headers({'test': 'header'})
    service.set_disable_ssl_verification(True)
    prepped = service.prepare_request('GET', url='')
    detailed_response = service.send(prepped)
    assert detailed_response.get_result() == {'foo': 'bar'}


@responses.activate
def test_request_success_invalid_json():
    # expect an ApiException with JSONDecodeError as the cause when a "success"
    # response contains invalid JSON in response body.
    with pytest.raises(ApiException, match=r'Error processing the HTTP response') as err:
        responses.add(
            responses.GET,
            'https://gateway.watsonplatform.net/test/api',
            status=200,
            body='{ "invalid": "json", "response"',
            content_type='application/json; charset=utf8',
        )
        service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
        prepped = service.prepare_request('GET', url='')
        service.send(prepped)
    assert err.value.code == 200
    assert err.value.http_response.headers['Content-Type'] == 'application/json; charset=utf8'
    assert isinstance(err.value.__cause__, requests.exceptions.JSONDecodeError)
    assert "Expecting ':' delimiter: line 1" in str(err.value.__cause__)


@responses.activate
def test_request_success_response():
    expected_body = '{"foo": "bar", "description": "this\nis\na\ndescription"}'
    responses.add(
        responses.GET,
        'https://gateway.watsonplatform.net/test/api',
        status=200,
        body=expected_body,
        content_type='application/json',
    )
    service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
    prepped = service.prepare_request('GET', url='')
    detailed_response = service.send(prepped)
    assert detailed_response.get_result() == {"foo": "bar", "description": "this\nis\na\ndescription"}


@responses.activate
def test_request_success_nonjson():
    responses.add(
        responses.GET,
        'https://gateway.watsonplatform.net/test/api',
        status=200,
        body='<h1>Hola, amigo!</h1>',
        content_type='text/html',
    )
    service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
    prepped = service.prepare_request('GET', url='')
    detailed_response = service.send(prepped)
    # It's odd that we have to call ".text" to get the string value
    # (see issue 3557)
    assert detailed_response.get_result().text == '<h1>Hola, amigo!</h1>'


@responses.activate
def test_request_fail_401_nonerror_json():
    # response body not an error object, so we expect the default error message.
    error_msg = 'Unauthorized: Access is denied due to invalid credentials'
    with pytest.raises(ApiException, match=error_msg) as err:
        responses.add(
            responses.GET,
            'https://gateway.watsonplatform.net/test/api',
            status=401,
            body=json.dumps({'foo': 'bar'}),
            content_type='application/json',
        )
        service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
        prepped = service.prepare_request('GET', url='')
        service.send(prepped)
    assert err.value.code == 401
    assert err.value.http_response.headers['Content-Type'] == 'application/json'
    assert err.value.message == error_msg


@responses.activate
def test_request_fail_401_error_json():
    # response body is an error object, so we expect to get the message from there.
    error_msg = 'You dont need to know...'
    with pytest.raises(ApiException, match=error_msg) as err:
        responses.add(
            responses.GET,
            'https://gateway.watsonplatform.net/test/api',
            status=401,
            body=json.dumps({'message': error_msg}),
            content_type='application/json',
        )
        service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
        prepped = service.prepare_request('GET', url='')
        service.send(prepped)
    assert err.value.code == 401
    assert err.value.http_response.headers['Content-Type'] == 'application/json'
    assert err.value.message == error_msg


@responses.activate
def test_request_fail_401_nonjson():
    response_body = 'You dont have a need to know...'
    with pytest.raises(ApiException, match=response_body) as err:
        responses.add(
            responses.GET,
            'https://gateway.watsonplatform.net/test/api',
            status=401,
            body=response_body,
            content_type='text/plain',
        )
        service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
        prepped = service.prepare_request('GET', url='')
        service.send(prepped)
    assert err.value.code == 401
    assert err.value.http_response.headers['Content-Type'] == 'text/plain'
    assert err.value.message == response_body


@responses.activate
def test_request_fail_401_badjson():
    # if an error response contains invalid JSON, then we should
    # end up with 'Unknown error' as the message since we couldn't get
    # the actual error message from the response body.
    response_body = 'This is not a JSON object'
    with pytest.raises(ApiException, match=response_body) as err:
        responses.add(
            responses.GET,
            'https://gateway.watsonplatform.net/test/api',
            status=401,
            body=response_body,
            content_type='application/json',
        )
        service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
        prepped = service.prepare_request('GET', url='')
        service.send(prepped)
    assert err.value.code == 401
    assert err.value.http_response.headers['Content-Type'] == 'application/json'
    assert err.value.message == response_body


def test_misc_methods():
    class MockModel:
        def __init__(self, xyz=None):
            self.xyz = xyz

        def _to_dict(self):
            _dict = {}
            if hasattr(self, 'xyz') and self.xyz is not None:
                _dict['xyz'] = self.xyz
            return _dict

        @classmethod
        def _from_dict(cls, _dict):
            args = {}
            if 'xyz' in _dict:
                args['xyz'] = _dict.get('xyz')
            return cls(**args)

    mock = MockModel('foo')
    service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
    model1 = service._convert_model(mock)
    assert model1 == {'xyz': 'foo'}

    model2 = service._convert_model("{\"xyz\": \"foo\"}")
    assert model2 is not None
    assert model2['xyz'] == 'foo'

    temp = ['default', '123']
    res_str = service._convert_list(temp)
    assert res_str == 'default,123'

    temp2 = 'default123'
    res_str2 = service._convert_list(temp2)
    assert res_str2 == temp2


def test_default_headers():
    service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
    service.set_default_headers({'xxx': 'yyy'})
    assert service.default_headers == {'xxx': 'yyy'}
    with pytest.raises(TypeError):
        service.set_default_headers('xxx')


def test_set_service_url():
    service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
    with pytest.raises(ValueError) as err:
        service.set_service_url('{url}')
    assert (
        str(err.value) == 'The service url shouldn\'t start or end with curly brackets or quotes. '
        'Be sure to remove any {} and \" characters surrounding your service url'
    )

    service.set_service_url('my_url')


def test_http_client():
    auth = BasicAuthenticator('my_username', 'my_password')
    service = AnyServiceV1('2018-11-20', authenticator=auth)
    assert isinstance(service.get_http_client(), requests.sessions.Session)
    assert service.get_http_client().headers.get('Accept-Encoding') == 'gzip, deflate'

    new_http_client = requests.Session()
    new_http_client.headers.update({'Accept-Encoding': 'gzip'})
    service.set_http_client(http_client=new_http_client)
    assert service.get_http_client().headers.get('Accept-Encoding') == 'gzip'

    with pytest.raises(TypeError):
        service.set_http_client("bad_argument_type")


def test_get_authenticator():
    auth = BasicAuthenticator('my_username', 'my_password')
    service = AnyServiceV1('2018-11-20', authenticator=auth)
    assert service.get_authenticator() is not None


def test_gzip_compression():
    # Should return uncompressed data when gzip is off
    service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
    assert not service.get_enable_gzip_compression()
    prepped = service.prepare_request('GET', url='', data=json.dumps({"foo": "bar"}))
    assert prepped['data'] == b'{"foo": "bar"}'
    assert prepped['headers'].get('content-encoding') != 'gzip'

    # Should return compressed data when gzip is on
    service.set_enable_gzip_compression(True)
    assert service.get_enable_gzip_compression()
    prepped = service.prepare_request('GET', url='', data=json.dumps({"foo": "bar"}))
    assert prepped['data'] == gzip.compress(b'{"foo": "bar"}')
    assert prepped['headers'].get('content-encoding') == 'gzip'

    # Should return compressed data when gzip is on for non-json data
    assert service.get_enable_gzip_compression()
    prepped = service.prepare_request('GET', url='', data=b'rawdata')
    assert prepped['data'] == gzip.compress(b'rawdata')
    assert prepped['headers'].get('content-encoding') == 'gzip'

    # Should return compressed data when gzip is on for gzip file data
    assert service.get_enable_gzip_compression()
    with tempfile.TemporaryFile(mode='w+b') as t_f:
        with gzip.GzipFile(mode='wb', fileobj=t_f) as gz_f:
            gz_f.write(json.dumps({"foo": "bar"}).encode())
        with gzip.GzipFile(mode='rb', fileobj=t_f) as gz_f:
            gzip_data = gz_f.read()
        prepped = service.prepare_request('GET', url='', data=gzip_data)
        assert prepped['data'] == gzip.compress(t_f.read())
        assert prepped['headers'].get('content-encoding') == 'gzip'

    # Should return compressed json data when gzip is on for gzip file json data
    assert service.get_enable_gzip_compression()
    with tempfile.TemporaryFile(mode='w+b') as t_f:
        with gzip.GzipFile(mode='wb', fileobj=t_f) as gz_f:
            gz_f.write("rawdata".encode())
        with gzip.GzipFile(mode='rb', fileobj=t_f) as gz_f:
            gzip_data = gz_f.read()
        prepped = service.prepare_request('GET', url='', data=gzip_data)
        assert prepped['data'] == gzip.compress(t_f.read())
        assert prepped['headers'].get('content-encoding') == 'gzip'

    # Should return uncompressed data when content-encoding is set
    assert service.get_enable_gzip_compression()
    prepped = service.prepare_request(
        'GET', url='', headers={"content-encoding": "gzip"}, data=json.dumps({"foo": "bar"})
    )
    assert prepped['data'] == b'{"foo": "bar"}'
    assert prepped['headers'].get('content-encoding') == 'gzip'


def test_gzip_compression_external():
    # Should set gzip compression from external config
    file_path = os.path.join(os.path.dirname(__file__), '../resources/ibm-credentials-gzip.env')
    os.environ['IBM_CREDENTIALS_FILE'] = file_path
    service = IncludeExternalConfigService('v1', authenticator=NoAuthAuthenticator())
    assert service.service_url == 'https://mockurl'
    assert service.get_enable_gzip_compression() is True
    prepped = service.prepare_request('GET', url='', data=json.dumps({"foo": "bar"}))
    assert prepped['data'] == gzip.compress(b'{"foo": "bar"}')
    assert prepped['headers'].get('content-encoding') == 'gzip'


def test_retry_config_default():
    service = BaseService(service_url='https://mockurl/', authenticator=NoAuthAuthenticator())
    service.enable_retries()
    assert service.retry_config.total == 4
    assert service.retry_config.backoff_factor == 1.0
    assert service.http_client.get_adapter('https://').max_retries.total == 4

    # Ensure retries fail after 4 retries
    error = ConnectTimeoutError()
    retry = service.http_client.get_adapter('https://').max_retries
    retry = retry.increment(error=error)
    retry = retry.increment(error=error)
    retry = retry.increment(error=error)
    retry = retry.increment(error=error)
    with pytest.raises(MaxRetryError) as retry_err:
        retry.increment(error=error)
    assert retry_err.value.reason == error


def test_retry_config_disable():
    # Test disabling retries
    service = BaseService(service_url='https://mockurl/', authenticator=NoAuthAuthenticator())
    service.enable_retries()
    service.disable_retries()
    assert service.retry_config is None
    assert service.http_client.get_adapter('https://').max_retries.total == 0

    # Ensure retries are not started after one connection attempt
    error = ConnectTimeoutError()
    retry = service.http_client.get_adapter('https://').max_retries
    with pytest.raises(MaxRetryError) as retry_err:
        retry.increment(error=error)
    assert retry_err.value.reason == error


def test_retry_config_non_default():
    service = BaseService(service_url='https://mockurl/', authenticator=NoAuthAuthenticator())
    service.enable_retries(2, 0.3)
    assert service.retry_config.total == 2
    assert service.retry_config.backoff_factor == 0.3

    # Ensure retries fail after 2 retries
    error = ConnectTimeoutError()
    retry = service.http_client.get_adapter('https://').max_retries
    retry = retry.increment(error=error)
    retry = retry.increment(error=error)
    with pytest.raises(MaxRetryError) as retry_err:
        retry.increment(error=error)
    assert retry_err.value.reason == error


def test_retry_config_external():
    file_path = os.path.join(os.path.dirname(__file__), '../resources/ibm-credentials-retry.env')
    os.environ['IBM_CREDENTIALS_FILE'] = file_path
    service = IncludeExternalConfigService('v1', authenticator=NoAuthAuthenticator())
    assert service.retry_config.total == 3
    assert service.retry_config.backoff_factor == 0.2

    # Ensure retries fail after 3 retries
    error = ConnectTimeoutError()
    retry = service.http_client.get_adapter('https://').max_retries
    retry = retry.increment(error=error)
    retry = retry.increment(error=error)
    retry = retry.increment(error=error)
    with pytest.raises(MaxRetryError) as retry_err:
        retry.increment(error=error)
    assert retry_err.value.reason == error


@responses.activate
def test_user_agent_header():
    service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
    user_agent_header = service.user_agent_header
    assert user_agent_header is not None
    assert user_agent_header['User-Agent'] is not None

    responses.add(responses.GET, 'https://gateway.watsonplatform.net/test/api', status=200, body='some text')
    prepped = service.prepare_request('GET', url='', headers={'user-agent': 'my_user_agent'})
    response = service.send(prepped)
    assert response.get_result().request.headers.get('user-agent') == 'my_user_agent'

    prepped = service.prepare_request('GET', url='', headers=None)
    response = service.send(prepped)
    assert response.get_result().request.headers.get('user-agent') == user_agent_header['User-Agent']


@responses.activate
def test_reserved_keys(caplog):
    service = AnyServiceV1('2021-07-02', authenticator=NoAuthAuthenticator())
    responses.add(responses.GET, 'https://gateway.watsonplatform.net/test/api', status=200, body='some text')
    prepped = service.prepare_request('GET', url='', headers={'key': 'OK'})
    response = service.send(
        prepped, headers={'key': 'bad'}, method='POST', url='localhost', cookies=None, hooks={'response': []}
    )
    assert response.get_result().request.headers.get('key') == 'OK'
    assert response.get_result().request.url == 'https://gateway.watsonplatform.net/test/api'
    assert response.get_result().request.method == 'GET'
    assert response.get_result().request.hooks == {'response': []}
    assert caplog.record_tuples[0][2] == '"method" has been removed from the request'
    assert caplog.record_tuples[1][2] == '"url" has been removed from the request'
    assert caplog.record_tuples[2][2] == '"cookies" has been removed from the request'


@responses.activate
def test_ssl_error():
    responses.add(responses.GET, 'https://gateway.watsonplatform.net/test/api', body=requests.exceptions.SSLError())
    service = AnyServiceV1('2021-08-18', authenticator=NoAuthAuthenticator())
    with pytest.raises(requests.exceptions.SSLError):
        prepped = service.prepare_request('GET', url='')
        service.send(prepped)


def test_files_dict():
    service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())

    form_data = {}
    with open(
        os.path.join(os.path.dirname(__file__), '../resources/ibm-credentials-iam.env'), 'r', encoding='utf-8'
    ) as file:
        form_data['file1'] = (None, file, 'application/octet-stream')
    form_data['string1'] = (None, 'hello', 'text/plain')
    request = service.prepare_request('GET', url='', headers={'X-opt-out': True}, files=form_data)
    files = request['files']
    assert isinstance(files, list)
    assert len(files) == 2
    files_dict = dict(files)
    file1 = files_dict['file1']
    assert file1[0] == 'ibm-credentials-iam.env'
    string1 = files_dict['string1']
    assert string1[0] is None


def test_files_list():
    service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())

    form_data = []
    with open(
        os.path.join(os.path.dirname(__file__), '../resources/ibm-credentials-iam.env'), 'r', encoding='utf-8'
    ) as file:
        form_data.append(('file1', (None, file, 'application/octet-stream')))
    form_data.append(('string1', (None, 'hello', 'text/plain')))
    request = service.prepare_request('GET', url='', headers={'X-opt-out': True}, files=form_data)
    files = request['files']
    assert isinstance(files, list)
    assert len(files) == 2
    files_dict = dict(files)
    file1 = files_dict['file1']
    assert file1[0] == 'ibm-credentials-iam.env'
    string1 = files_dict['string1']
    assert string1[0] is None


def test_files_duplicate_parts():
    service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())

    form_data = []
    with open(
        os.path.join(os.path.dirname(__file__), '../resources/ibm-credentials-iam.env'), 'r', encoding='utf-8'
    ) as file:
        form_data.append(('creds_file', (None, file, 'application/octet-stream')))
    with open(
        os.path.join(os.path.dirname(__file__), '../resources/ibm-credentials-basic.env'), 'r', encoding='utf-8'
    ) as file:
        form_data.append(('creds_file', (None, file, 'application/octet-stream')))
    with open(
        os.path.join(os.path.dirname(__file__), '../resources/ibm-credentials-bearer.env'), 'r', encoding='utf-8'
    ) as file:
        form_data.append(('creds_file', (None, file, 'application/octet-stream')))
    request = service.prepare_request('GET', url='', headers={'X-opt-out': True}, files=form_data)
    files = request['files']
    assert isinstance(files, list)
    assert len(files) == 3
    for part_name, file_tuple in files:
        assert part_name == 'creds_file'
        assert file_tuple[0] is not None


def test_json():
    service = AnyServiceV1('2018-11-20', authenticator=NoAuthAuthenticator())
    req = service.prepare_request('POST', url='', headers={'X-opt-out': True}, data={'hello': 'world', 'fóó': 'bår'})
    assert req.get('data') == b'{"hello": "world", "f\\u00f3\\u00f3": "b\\u00e5r"}'


def test_service_url_handling():
    service = AnyServiceV1('2018-11-20', service_url='https://host///////', authenticator=NoAuthAuthenticator())
    assert service.service_url == 'https://host'

    service.set_service_url('https://host/')
    assert service.service_url == 'https://host'

    req = service.prepare_request('POST', url='/path/', headers={'X-opt-out': True}, data={'hello': 'world'})
    assert req.get('url') == 'https://host/path/'

    service = AnyServiceV1('2018-11-20', service_url='https://host/', authenticator=NoAuthAuthenticator())
    assert service.service_url == 'https://host'

    service.set_service_url('https://host/')
    assert service.service_url == 'https://host'

    req = service.prepare_request('POST', url='/', headers={'X-opt-out': True}, data={'hello': 'world'})
    assert req.get('url') == 'https://host/'

    req = service.prepare_request('POST', url='////', headers={'X-opt-out': True}, data={'hello': 'world'})
    assert req.get('url') == 'https://host/'

    service.set_service_url(None)
    assert service.service_url is None

    service = AnyServiceV1('2018-11-20', service_url='/', authenticator=NoAuthAuthenticator())
    assert service.service_url == ''

    service.set_service_url('/')
    assert service.service_url == ''

    with pytest.raises(ValueError) as err:
        service.prepare_request('POST', url='/', headers={'X-opt-out': True}, data={'hello': 'world'})
    assert str(err.value) == 'The service_url is required'


def test_service_url_slash():
    service = AnyServiceV1('2018-11-20', service_url='/', authenticator=NoAuthAuthenticator())
    assert service.service_url == ''
    with pytest.raises(ValueError) as err:
        service.prepare_request('POST', url='/', headers={'X-opt-out': True}, data={'hello': 'world'})
    assert str(err.value) == 'The service_url is required'


def test_service_url_not_set():
    service = BaseService(service_url='', authenticator=NoAuthAuthenticator())
    with pytest.raises(ValueError) as err:
        service.prepare_request('POST', url='')
    assert str(err.value) == 'The service_url is required'


def test_setting_proxy():
    service = BaseService(service_url='test', authenticator=IAMAuthenticator('wonder woman'))
    assert service.authenticator is not None
    assert service.authenticator.token_manager.http_config == {}

    http_config = {"proxies": {"http": "user:password@host:port"}}
    service.set_http_config(http_config)
    assert service.authenticator.token_manager.http_config == http_config

    service2 = BaseService(service_url='test', authenticator=BasicAuthenticator('marvellous', 'mrs maisel'))
    service2.set_http_config(http_config)
    assert service2.authenticator is not None


def test_configure_service():
    file_path = os.path.join(os.path.dirname(__file__), '../resources/ibm-credentials-external.env')
    os.environ['IBM_CREDENTIALS_FILE'] = file_path
    service = IncludeExternalConfigService('v1', authenticator=NoAuthAuthenticator())
    assert service.service_url == 'https://externallyconfigured.com/api'
    assert service.disable_ssl_verification is True
    # The authenticator should not be changed as a result of configure_service()
    assert isinstance(service.get_authenticator(), NoAuthAuthenticator)


def test_configure_service_error():
    service = BaseService(service_url='v1', authenticator=NoAuthAuthenticator())
    with pytest.raises(ValueError) as err:
        service.configure_service(None)
    assert str(err.value) == 'Service_name must be of type string.'


def test_min_ssl_version():
    service = AnyServiceV1('2022-03-08', authenticator=NoAuthAuthenticator())
    adapter = service.http_client.get_adapter('https://')
    ssl_context = adapter.poolmanager.connection_pool_kw.get('ssl_context', None)
    assert ssl_context is not None
    assert ssl_context.minimum_version == ssl.TLSVersion.TLSv1_2
