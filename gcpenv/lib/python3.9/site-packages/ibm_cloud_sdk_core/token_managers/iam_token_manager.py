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

from .iam_request_based_token_manager import IAMRequestBasedTokenManager


class IAMTokenManager(IAMRequestBasedTokenManager):
    """The IAMTokenManager takes an api key and performs the necessary interactions with
    the IAM token service to obtain and store a suitable bearer token. Additionally, the IAMTokenManager
    If the current stored bearer token has expired a new bearer token will be retrieved.

    Attributes:
        apikey: A generated API key from ibmcloud.
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

    Args:
        apikey: A generated APIKey from ibmcloud.

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

    def __init__(
        self,
        apikey: str,
        *,
        url: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        disable_ssl_verification: bool = False,
        headers: Optional[Dict[str, str]] = None,
        proxies: Optional[Dict[str, str]] = None,
        scope: Optional[str] = None
    ) -> None:
        super().__init__(
            url=url,
            client_id=client_id,
            client_secret=client_secret,
            disable_ssl_verification=disable_ssl_verification,
            headers=headers,
            proxies=proxies,
            scope=scope,
        )

        self.apikey = apikey

        # Set API key related data.
        self.request_payload['grant_type'] = 'urn:ibm:params:oauth:grant-type:apikey'
        self.request_payload['apikey'] = self.apikey
        self.request_payload['response_type'] = 'cloud_iam'
