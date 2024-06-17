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

import json
from typing import Dict, Optional

from .jwt_token_manager import JWTTokenManager


class CP4DTokenManager(JWTTokenManager):
    """Token Manager of CloudPak for data.

    The Token Manager performs basic auth with a username and password
    to acquire JWT tokens.

    Keyword Arguments:
        username: The username for authentication [required].
        password: The password for authentication [required if apikey not specified].
        url: The endpoint for JWT token requests [required].
        apikey: The apikey for authentication [required if password not specified].
        disable_ssl_verification: Disable ssl verification. Defaults to False.
        headers: Headers to be sent with every service token request. Defaults to None.
        proxies: Proxies to use for making request. Defaults to None.
        proxies.http (optional): The proxy endpoint to use for HTTP requests.
        proxies.https (optional): The proxy endpoint to use for HTTPS requests.
        verify (optional): The path to the certificate to use for HTTPS requests.

    Attributes:
        username (str): The username for authentication.
        password (str): The password for authentication.
        url (str): The endpoint for JWT token requests.
        headers (dict): Headers to be sent with every service token request.
        proxies (dict): Proxies to use for making token requests.
        proxies.http (str): The proxy endpoint to use for HTTP requests.
        proxies.https (str): The proxy endpoint to use for HTTPS requests.
        verify (str): The path to the certificate to use for HTTPS requests.
    """

    TOKEN_NAME = 'token'
    VALIDATE_AUTH_PATH = '/v1/authorize'

    def __init__(
        self,
        username: str = None,
        password: str = None,
        url: str = None,
        *,
        apikey: str = None,
        disable_ssl_verification: bool = False,
        headers: Optional[Dict[str, str]] = None,
        proxies: Optional[Dict[str, str]] = None,
        verify: Optional[str] = None
    ) -> None:
        self.username = username
        self.password = password
        self.verify = verify
        if url and not self.VALIDATE_AUTH_PATH in url:
            url = url + '/v1/authorize'
        self.apikey = apikey
        self.headers = headers
        if self.headers is None:
            self.headers = {}
        self.headers['Content-Type'] = 'application/json'
        self.proxies = proxies
        super().__init__(url, disable_ssl_verification=disable_ssl_verification, token_name=self.TOKEN_NAME)

    def request_token(self) -> dict:
        """Makes a request for a token."""
        response = self._request(
            method='POST',
            headers=self.headers,
            url=self.url,
            data=json.dumps({"username": self.username, "password": self.password, "api_key": self.apikey}),
            proxies=self.proxies,
            verify=self.verify,
        )
        return response

    def set_headers(self, headers: Dict[str, str]) -> None:
        """Headers to be sent with every CP4D token request.

        Args:
            headers: The headers to be sent with every CP4D token request.
        """
        if isinstance(headers, dict):
            self.headers = headers
        else:
            raise TypeError('headers must be a dictionary')

    def set_proxies(self, proxies: Dict[str, str]) -> None:
        """Sets the proxies the token manager will use to communicate with CP4D on behalf of the host.

        Args:
            proxies: Proxies to use for making request. Defaults to None.
            proxies.http (optional): The proxy endpoint to use for HTTP requests.
            proxies.https (optional): The proxy endpoint to use for HTTPS requests.
        """
        if isinstance(proxies, dict):
            self.proxies = proxies
        else:
            raise TypeError('proxies must be a dictionary')
