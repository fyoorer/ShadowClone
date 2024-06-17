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

from typing import Dict, Optional

from .jwt_token_manager import JWTTokenManager


# pylint: disable=too-many-instance-attributes
class IAMRequestBasedTokenManager(JWTTokenManager):
    """The IamRequestBasedTokenManager class contains code relevant to any token manager that
    interacts with the IAM service to manage a token. It stores information relevant to all
    IAM requests, such as the client ID and secret, and performs the token request with a set
    of request options common to any IAM token management scheme.

    If the current stored bearer token has expired a new bearer token will be retrieved.

    Attributes:
        request_payload(dict): the data that will be sent in the IAM OAuth token request
        url (str): The IAM endpoint to token requests.
        client_id (str): The client_id and client_secret fields are used to form
            a "basic auth" Authorization header for interactions with the IAM token server.
        client_secret (str): The client_id and client_secret fields are used to form
            a "basic auth" Authorization header for interactions with the IAM token server.
        headers (dict): Default headers to be sent with every IAM token request.
        proxies (dict): Proxies to use for communicating with IAM.
        proxies.http (str): The proxy endpoint to use for HTTP requests.
        proxies.https (str): The proxy endpoint to use for HTTPS requests.
        http_config (dict): A dictionary containing values that control the timeout, proxies, and etc of HTTP requests.
        scope (str): The "scope" to use when fetching the bearer token from the IAM token server.
        This can be used to obtain an access token with a specific scope.

    Keyword Args:
        url: The IAM endpoint to token requests. Defaults to None.
        client_id: The client_id and client_secret fields are used to form
            a "basic auth" Authorization header for interactions with the IAM token server.
            Defaults to None.
        client_secret: The client_id and client_secret fields are used to form
            a "basic auth" Authorization header for interactions with the IAM token server.
            Defaults to None.
        disable_ssl_verification: A flag that indicates whether verification of
            the server's SSL certificate should be disabled or not. Defaults to False.
        headers: Default headers to be sent with every IAM token request. Defaults to None.
        proxies: Proxies to use for communicating with IAM. Defaults to None.
        proxies.http: The proxy endpoint to use for HTTP requests.
        proxies.https: The proxy endpoint to use for HTTPS requests.
        scope: The "scope" to use when fetching the bearer token from the IAM token server.
        This can be used to obtain an access token with a specific scope.
    """

    DEFAULT_IAM_URL = 'https://iam.cloud.ibm.com'
    OPERATION_PATH = "/identity/token"

    def __init__(
        self,
        url: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        disable_ssl_verification: bool = False,
        headers: Optional[Dict[str, str]] = None,
        proxies: Optional[Dict[str, str]] = None,
        scope: Optional[str] = None,
    ) -> None:
        if not url:
            url = self.DEFAULT_IAM_URL
        if url.endswith(self.OPERATION_PATH):
            url = url[: -len(self.OPERATION_PATH)]
        self.url = url
        self.client_id = client_id
        self.client_secret = client_secret
        self.headers = headers
        self.refresh_token = None
        self.proxies = proxies
        self.scope = scope
        self.request_payload = {}
        super().__init__(self.url, disable_ssl_verification=disable_ssl_verification, token_name='access_token')

    def request_token(self) -> dict:
        """Request an IAM OAuth token given an API Key.

        If client_id and client_secret are specified use their values as a user and pass auth set
        according to WHATWG url spec.

        Returns:
             A dictionary containing the bearer token to be subsequently used service requests.
        """
        headers = {'Content-type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
        if self.headers is not None and isinstance(self.headers, dict):
            headers.update(self.headers)

        data = dict(self.request_payload)

        if self.scope is not None and self.scope:
            data['scope'] = self.scope

        auth_tuple = None
        # If both the client_id and secret were specified by the user, then use them
        if self.client_id and self.client_secret:
            auth_tuple = (self.client_id, self.client_secret)

        response = self._request(
            method='POST',
            url=(self.url + self.OPERATION_PATH) if self.url else self.url,
            headers=headers,
            data=data,
            auth_tuple=auth_tuple,
            proxies=self.proxies,
        )
        return response

    def set_client_id_and_secret(self, client_id: str, client_secret: str) -> None:
        """Set the client_id and client_secret.

        Args:
            client_id: The client id to be used for token requests.
            client_secret: The client secret to be used for token requests.
        """
        self.client_id = client_id
        self.client_secret = client_secret

    def set_headers(self, headers: Dict[str, str]) -> None:
        """Headers to be sent with every CP4D token request.

        Args:
            headers: Headers to be sent with every IAM token request.
        """
        if isinstance(headers, dict):
            self.headers = headers
        else:
            raise TypeError('headers must be a dictionary')

    def _save_token_info(self, token_response: dict) -> None:
        super()._save_token_info(token_response)

        self.refresh_token = token_response.get("refresh_token")

    def set_proxies(self, proxies: Dict[str, str]) -> None:
        """Sets the proxies the token manager will use to communicate with IAM on behalf of the host.

        Args:
            proxies: Proxies to use for communicating with IAM.
            proxies.http (str, optional): The proxy endpoint to use for HTTP requests.
            proxies.https (str, optional): The proxy endpoint to use for HTTPS requests.
        """
        if isinstance(proxies, dict):
            self.proxies = proxies
        else:
            raise TypeError('proxies must be a dictionary')

    def set_scope(self, value: str) -> None:
        """Sets the "scope" parameter to use when fetching the bearer token from the IAM token server.

        Args:
            value: A space seperated string that makes up the scope parameter.
        """
        self.scope = value
