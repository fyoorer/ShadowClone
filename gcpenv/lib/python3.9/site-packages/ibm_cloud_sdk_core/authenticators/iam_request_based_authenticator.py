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

from typing import Dict

from requests import Request

from .authenticator import Authenticator


class IAMRequestBasedAuthenticator(Authenticator):
    """The IAMRequestBasedAuthenticator class contains code that is common to all authenticators
    that need to interact with the IAM tokens service to obtain an access token.

    The bearer token will be sent as an Authorization header in the form:

        Authorization: Bearer <bearer-token>

    Attributes:
        token_manager (TokenManager): Retrieves and manages IAM tokens from the endpoint specified by the url.
    """

    def validate(self) -> None:
        """Validates the client_id, and client_secret for IAM token requests.

        Ensure both the client_id and client_secret are set if either of them are defined.

        Raises:
            ValueError: The client_id, and/or client_secret are not valid for IAM token requests.
        """
        if (self.token_manager.client_id and not self.token_manager.client_secret) or (
            not self.token_manager.client_id and self.token_manager.client_secret
        ):
            raise ValueError('Both client_id and client_secret should be initialized.')

    def authenticate(self, req: Request) -> None:
        """Adds IAM authentication information to the request.

        The IAM bearer token will be added to the request's headers in the form:

            Authorization: Bearer <bearer-token>

        Args:
            req: The request to add IAM authentication information too. Must contain a key to a dictionary
            called headers.
        """
        headers = req.get('headers')
        bearer_token = self.token_manager.get_token()
        headers['Authorization'] = 'Bearer {0}'.format(bearer_token)

    def set_client_id_and_secret(self, client_id: str, client_secret: str) -> None:
        """Set the client_id and client_secret pair the token manager will use for IAM token requests.

        Args:
            client_id: The client id to be used in basic auth.
            client_secret: The client secret to be used in basic auth.

        Raises:
            ValueError: The apikey, client_id, and/or client_secret are not valid for IAM token requests.
        """
        self.token_manager.set_client_id_and_secret(client_id, client_secret)
        self.validate()

    def set_disable_ssl_verification(self, status: bool = False) -> None:
        """Set the flag that indicates whether verification of the server's SSL certificate should be
        disabled or not. Defaults to False.

        Args:
            status: Headers to be sent with every IAM token request. Defaults to None

        Raises:
            TypeError: The `status` is not a bool.
        """
        self.token_manager.set_disable_ssl_verification(status)

    def set_headers(self, headers: Dict[str, str]) -> None:
        """Headers to be sent with every IAM token request.

        Args:
            headers: Headers to be sent with every IAM token request.
        """
        self.token_manager.set_headers(headers)

    def set_proxies(self, proxies: Dict[str, str]) -> None:
        """Sets the proxies the token manager will use to communicate with IAM on behalf of the host.

        Args:
            proxies: Dictionary for mapping request protocol to proxy URL.
            proxies.http (optional): The proxy endpoint to use for HTTP requests.
            proxies.https (optional): The proxy endpoint to use for HTTPS requests.
        """
        self.token_manager.set_proxies(proxies)

    def set_scope(self, value: str) -> None:
        """Sets the "scope" parameter to use when fetching the bearer token from the IAM token server.
        This can be used to obtain an access token with a specific scope.

        Args:
            value: A space seperated string that makes up the scope parameter.
        """
        self.token_manager.set_scope(value)
