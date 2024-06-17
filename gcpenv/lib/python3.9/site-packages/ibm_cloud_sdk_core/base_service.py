# coding: utf-8

# Copyright 2019 IBM All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import gzip
import json as json_import
import logging
import platform
from http.cookiejar import CookieJar
from os.path import basename
from typing import Dict, List, Optional, Tuple, Union
from urllib3.util.retry import Retry

import requests
from requests.structures import CaseInsensitiveDict
from requests.exceptions import JSONDecodeError

from ibm_cloud_sdk_core.authenticators import Authenticator
from .api_exception import ApiException
from .detailed_response import DetailedResponse
from .token_managers.token_manager import TokenManager
from .utils import (
    has_bad_first_or_last_char,
    is_json_mimetype,
    remove_null_values,
    cleanup_values,
    read_external_sources,
    strip_extra_slashes,
    SSLHTTPAdapter,
)
from .version import __version__

# Uncomment this to enable http debugging
# import http.client as http_client
# http_client.HTTPConnection.debuglevel = 1


logger = logging.getLogger(__name__)


# pylint: disable=too-many-instance-attributes
# pylint: disable=too-many-locals
class BaseService:
    """Common functionality shared by generated service classes.

    The base service authenticates requests via its authenticator, stores cookies, and
    wraps responses from the service endpoint in DetailedResponse or APIException objects.

    Keyword Arguments:
        service_url: Url to the service endpoint. Defaults to None.
        authenticator: Adds authentication data to service requests. Defaults to None.
        disable_ssl_verification: A flag that indicates whether verification of the server's SSL
            certificate should be disabled or not. Defaults to False.
        enable_gzip_compression: A flag that indicates whether to enable gzip compression on request bodies

    Attributes:
        service_url (str): Url to the service endpoint.
        authenticator (Authenticator): Adds authentication data to service requests.
        disable_ssl_verification (bool): A flag that indicates whether verification of
            the server's SSL certificate should be disabled or not.
        default_headers (dict): A dictionary of headers to be sent with every HTTP request to the service endpoint.
        jar (http.cookiejar.CookieJar): Stores cookies received from the service.
        http_config (dict): A dictionary containing values that control the timeout, proxies, and etc of HTTP requests.
        http_client (Session): A configurable session which can use Transport Adapters to configure retries, timeouts,
            proxies, etc. globally for all requests.
        enable_gzip_compression (bool): A flag that indicates whether to enable gzip compression on request bodies
    Raises:
        ValueError: If Authenticator is not provided or invalid type.
    """

    SDK_NAME = 'ibm-python-sdk-core'
    ERROR_MSG_DISABLE_SSL = (
        'The connection failed because the SSL certificate is not valid. To use a self-signed '
        'certificate, disable verification of the server\'s SSL certificate by invoking the '
        'set_disable_ssl_verification(True) on your service instance and/ or use the '
        'disable_ssl_verification option of the authenticator.'
    )

    def __init__(
        self,
        *,
        service_url: str = None,
        authenticator: Authenticator = None,
        disable_ssl_verification: bool = False,
        enable_gzip_compression: bool = False
    ) -> None:
        self.set_service_url(service_url)
        self.http_client = requests.Session()
        self.http_config = {}
        self.jar = CookieJar()
        self.authenticator = authenticator
        self.disable_ssl_verification = disable_ssl_verification
        self.default_headers = None
        self.enable_gzip_compression = enable_gzip_compression
        self._set_user_agent_header(self._build_user_agent())
        self.retry_config = None
        self.http_adapter = SSLHTTPAdapter()
        if not self.authenticator:
            raise ValueError('authenticator must be provided')
        if not isinstance(self.authenticator, Authenticator):
            raise ValueError('authenticator should be of type Authenticator')

        self.http_client.mount('http://', self.http_adapter)
        self.http_client.mount('https://', self.http_adapter)

    def enable_retries(self, max_retries: int = 4, retry_interval: float = 1.0) -> None:
        """Enable automatic retries on the underlying http client used by the BaseService instance.

        Args:
          max_retries: the maximum number of retries to attempt for a failed retryable request
          retry_interval: the default wait time (in seconds) to use for the first retry attempt.
            In general, if a response includes the Retry-After header, that will be used for
            the wait time associated with the retry attempt.  If the Retry-After header is not
            present, then the wait time is based on the retry_interval and retry attempt number:
               wait_time = retry_interval * (2 ^ (n-1)), where n is the retry attempt number
        """
        self.retry_config = Retry(
            total=max_retries,
            backoff_factor=retry_interval,
            # List of HTTP status codes to retry on in addition to Timeout/Connection Errors
            status_forcelist=[429, 500, 502, 503, 504],
            # List of HTTP methods to retry on
            # Omitting this will default to all methods except POST
            allowed_methods=['HEAD', 'GET', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'POST'],
        )
        self.http_adapter = SSLHTTPAdapter(max_retries=self.retry_config)
        self.http_client.mount('http://', self.http_adapter)
        self.http_client.mount('https://', self.http_adapter)

    def disable_retries(self):
        """Remove retry config from http_adapter"""
        self.retry_config = None
        self.http_adapter = SSLHTTPAdapter()
        self.http_client.mount('http://', self.http_adapter)
        self.http_client.mount('https://', self.http_adapter)

    @staticmethod
    def _get_system_info() -> str:
        return '{0} {1} {2}'.format(
            platform.system(), platform.release(), platform.python_version()  # OS  # OS version  # Python version
        )

    def _build_user_agent(self) -> str:
        return '{0}-{1} {2}'.format(self.SDK_NAME, __version__, self._get_system_info())

    def configure_service(self, service_name: str) -> None:
        """Look for external configuration of a service. Set service properties.

        Try to get config from external sources, with the following priority:
        1. Credentials file(ibm-credentials.env)
        2. Environment variables
        3. VCAP Services(Cloud Foundry)

        Args:
            service_name: The service name

        Raises:
            ValueError: If service_name is not a string.
        """
        if not isinstance(service_name, str):
            raise ValueError('Service_name must be of type string.')

        config = read_external_sources(service_name)
        if config.get('URL'):
            self.set_service_url(config.get('URL'))
        if config.get('DISABLE_SSL'):
            self.set_disable_ssl_verification(config.get('DISABLE_SSL').lower() == 'true')
        if config.get('ENABLE_GZIP'):
            self.set_enable_gzip_compression(config.get('ENABLE_GZIP').lower() == 'true')
        if config.get('ENABLE_RETRIES'):
            if config.get('ENABLE_RETRIES').lower() == 'true':
                kwargs = {}
                if config.get('MAX_RETRIES'):
                    kwargs["max_retries"] = int(config.get('MAX_RETRIES'))
                if config.get('RETRY_INTERVAL'):
                    kwargs["retry_interval"] = float(config.get('RETRY_INTERVAL'))
                self.enable_retries(**kwargs)

    def _set_user_agent_header(self, user_agent_string: str) -> None:
        self.user_agent_header = {'User-Agent': user_agent_string}

    def set_http_config(self, http_config: dict) -> None:
        """Sets the http config dictionary.

        The dictionary can contain values that control the timeout, proxies, and etc of HTTP requests.

        Arguments:
            http_config: Configuration values to customize HTTP behaviors.

        Raises:
            TypeError: http_config is not a dict.
        """
        if isinstance(http_config, dict):
            self.http_config = http_config
            if (
                self.authenticator
                and hasattr(self.authenticator, 'token_manager')
                and isinstance(self.authenticator.token_manager, TokenManager)
            ):
                self.authenticator.token_manager.http_config = http_config
        else:
            raise TypeError("http_config parameter must be a dictionary")

    def set_disable_ssl_verification(self, status: bool = False) -> None:
        """Set the flag that indicates whether verification of
        the server's SSL certificate should be disabled or not.

        Keyword Arguments:
            status: set to true to disable ssl verification (default: {False})
        """
        self.disable_ssl_verification = status

    def set_service_url(self, service_url: str) -> None:
        """Set the url the service will make HTTP requests too.

        Arguments:
            service_url: The WHATWG URL standard origin ex. https://example.service.com

        Raises:
            ValueError: Improperly formatted service_url
        """
        if has_bad_first_or_last_char(service_url):
            raise ValueError(
                'The service url shouldn\'t start or end with curly brackets or quotes. '
                'Be sure to remove any {} and \" characters surrounding your service url'
            )
        if service_url is not None:
            service_url = service_url.rstrip('/')
        self.service_url = service_url

    def get_http_client(self) -> requests.sessions.Session:
        """Get the http client session currently used by the service.

        Returns:
            The http client session currently used by the service.
        """
        return self.http_client

    def set_http_client(self, http_client: requests.sessions.Session) -> None:
        """Set current http client session

        Arguments:
            http_client: A new requests session client
        """
        if isinstance(http_client, requests.sessions.Session):
            self.http_client = http_client
        else:
            raise TypeError("http_client parameter must be a requests.sessions.Session")

    def get_authenticator(self) -> Authenticator:
        """Get the authenticator currently used by the service.

        Returns:
            The authenticator currently used by the service.
        """
        return self.authenticator

    def set_default_headers(self, headers: Dict[str, str]) -> None:
        """Set http headers to be sent in every request.

        Arguments:
            headers: A dictionary of headers
        """
        if isinstance(headers, dict):
            self.default_headers = headers
        else:
            raise TypeError("headers parameter must be a dictionary")

    def send(self, request: requests.Request, **kwargs) -> DetailedResponse:
        """Send a request and wrap the response in a DetailedResponse or APIException.

        Args:
            request: The request to send to the service endpoint.

        Raises:
            ApiException: The exception from the API.

        Returns:
            The response from the request.
        """
        # Use a one minute timeout when our caller doesn't give a timeout.
        # http://docs.python-requests.org/en/master/user/quickstart/#timeouts
        kwargs = dict({"timeout": 60}, **kwargs)
        kwargs = dict(kwargs, **self.http_config)

        if self.disable_ssl_verification:
            kwargs['verify'] = False

        # Check to see if the caller specified the 'stream' argument.
        stream_response = kwargs.get('stream') or False

        # Remove the keys we set manually, don't let the user to overwrite these.
        reserved_keys = ['method', 'url', 'headers', 'params', 'cookies']
        silent_keys = ['headers']
        for key in reserved_keys:
            if key in kwargs:
                del kwargs[key]
                if key not in silent_keys:
                    logger.warning('"%s" has been removed from the request', key)
        try:
            response = self.http_client.request(**request, cookies=self.jar, **kwargs)

            # Process a "success" response.
            if 200 <= response.status_code <= 299:
                if response.status_code == 204 or request['method'] == 'HEAD':
                    # There is no body content for a HEAD response or a 204 response.
                    result = None
                elif stream_response:
                    result = response
                elif not response.text:
                    result = None
                elif is_json_mimetype(response.headers.get('Content-Type')):
                    # If this is a JSON response, then try to unmarshal it.
                    try:
                        result = response.json(strict=False)
                    except JSONDecodeError as err:
                        raise ApiException(
                            code=response.status_code,
                            http_response=response,
                            message='Error processing the HTTP response',
                        ) from err
                else:
                    # Non-JSON response, just use response body as-is.
                    result = response

                return DetailedResponse(response=result, headers=response.headers, status_code=response.status_code)

            # Received error status code from server, raise an APIException.
            raise ApiException(response.status_code, http_response=response)
        except requests.exceptions.SSLError:
            logger.exception(self.ERROR_MSG_DISABLE_SSL)
            raise

    def set_enable_gzip_compression(self, should_enable_compression: bool = False) -> None:
        """Set value to enable gzip compression on request bodies"""
        self.enable_gzip_compression = should_enable_compression

    def get_enable_gzip_compression(self) -> bool:
        """Get value for enabling gzip compression on request bodies"""
        return self.enable_gzip_compression

    def prepare_request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        data: Optional[Union[str, dict]] = None,
        files: Optional[Union[Dict[str, Tuple[str]], List[Tuple[str, Tuple[str, ...]]]]] = None,
        **kwargs
    ) -> dict:
        """Build a dict that represents an HTTP service request.

        Clean up headers, add default http configuration, convert data
        into json, process files, and merge all into a single request dict.

        Args:
            method: The HTTP method of the request ex. GET, POST, etc.
            url: The origin + pathname according to WHATWG spec.

        Keyword Arguments:
            headers: Headers of the request.
            params: Querystring data to be appended to the url.
            data: The request body. Converted to json if a dict.
            files: 'files' can be a dictionary (i.e { '<part-name>': (<tuple>)}),
                or a list of tuples [ (<part-name>, (<tuple>))... ]

        Returns:
            Prepared request dictionary.
        """
        # pylint: disable=unused-argument; necessary for kwargs
        request = {'method': method}

        # validate the service url is set
        if not self.service_url:
            raise ValueError('The service_url is required')

        # Combine the service_url and operation path to form the request url.
        # Note: we have already stripped any trailing slashes from the service_url
        # and we know that the operation path ('url') will start with a slash.
        request['url'] = strip_extra_slashes(self.service_url + url)

        headers = remove_null_values(headers) if headers else {}
        headers = cleanup_values(headers)
        headers = CaseInsensitiveDict(headers)
        if self.default_headers is not None:
            headers.update(self.default_headers)
        if 'user-agent' not in headers:
            headers.update(self.user_agent_header)
        request['headers'] = headers

        params = remove_null_values(params)
        params = cleanup_values(params)
        request['params'] = params

        if isinstance(data, str):
            data = data.encode('utf-8')
        elif isinstance(data, dict) and data:
            data = remove_null_values(data)
            if headers.get('content-type') is None:
                headers.update({'content-type': 'application/json'})
            data = json_import.dumps(data).encode('utf-8')
        request['data'] = data

        self.authenticator.authenticate(request)

        # Compress the request body if applicable
        if self.get_enable_gzip_compression() and 'content-encoding' not in headers and request['data'] is not None:
            headers['content-encoding'] = 'gzip'
            uncompressed_data = request['data']
            request_body = gzip.compress(uncompressed_data)
            request['data'] = request_body
            request['headers'] = headers

        # Next, we need to process the 'files' argument to try to fill in
        # any missing filenames where possible.
        # 'files' can be a dictionary (i.e { '<part-name>': (<tuple>)} )
        # or a list of tuples [ (<part-name>, (<tuple>))... ]
        # If 'files' is a dictionary we'll convert it to a list of tuples.
        new_files = []
        if files is not None:
            # If 'files' is a dictionary, transform it into a list of tuples.
            if isinstance(files, dict):
                files = remove_null_values(files)
                files = files.items()
            # Next, fill in any missing filenames from file tuples.
            for part_name, file_tuple in files:
                if file_tuple and len(file_tuple) == 3 and file_tuple[0] is None:
                    file = file_tuple[1]
                    if file and hasattr(file, 'name'):
                        filename = basename(file.name)
                        file_tuple = (filename, file_tuple[1], file_tuple[2])
                new_files.append((part_name, file_tuple))
        request['files'] = new_files
        return request

    @staticmethod
    def encode_path_vars(*args: str) -> List[str]:
        """Encode path variables to be substituted into a URL path.

        Arguments:
            args: A list of strings to be URL path encoded

        Returns:
            A list of encoded strings that are safe to substitute into a URL path.
        """
        return (requests.utils.quote(x, safe='') for x in args)

    # The methods below are kept for compatibility and should be removed
    # in the next major release.

    # pylint: disable=protected-access

    @staticmethod
    def _convert_model(val: str) -> None:
        if isinstance(val, str):
            val = json_import.loads(val)
        if hasattr(val, "_to_dict"):
            return val._to_dict()
        return val

    @staticmethod
    def _convert_list(val: list) -> None:
        if isinstance(val, list):
            return ",".join(val)
        return val

    @staticmethod
    def _encode_path_vars(*args) -> None:
        return (requests.utils.quote(x, safe='') for x in args)
