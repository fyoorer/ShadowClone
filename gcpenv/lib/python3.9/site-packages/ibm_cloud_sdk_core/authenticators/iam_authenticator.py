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

from .authenticator import Authenticator
from .iam_request_based_authenticator import IAMRequestBasedAuthenticator
from ..token_managers.iam_token_manager import IAMTokenManager
from ..utils import has_bad_first_or_last_char


class IAMAuthenticator(IAMRequestBasedAuthenticator):
    """The IAMAuthenticator utilizes an apikey, or client_id and client_secret pair to
    obtain a suitable bearer token, and adds it to requests.

    The bearer token will be sent as an Authorization header in the form:

        Authorization: Bearer <bearer-token>

    Args:
        apikey: The IAM api key.

    Keyword Args:
        url: The URL representing the IAM token service endpoint. If not specified, a suitable default value is used.
        client_id: The client_id and client_secret fields are used to form
            a "basic" authorization header for IAM token requests. Defaults to None.
        client_secret: The client_id and client_secret fields are used to form
            a "basic" authorization header for IAM token requests. Defaults to None.
        disable_ssl_verification: A flag that indicates whether verification of
        the server's SSL certificate should be disabled or not. Defaults to False.
        headers: Default headers to be sent with every IAM token request. Defaults to None.
        proxies: Dictionary for mapping request protocol to proxy URL. Defaults to None.
        proxies.http (optional): The proxy endpoint to use for HTTP requests.
        proxies.https (optional): The proxy endpoint to use for HTTPS requests.
        scope: The "scope" to use when fetching the bearer token from the IAM token server.
        This can be used to obtain an access token with a specific scope.

    Attributes:
        token_manager (IAMTokenManager): Retrieves and manages IAM tokens from the endpoint specified by the url.

    Raises:
        TypeError: The `disable_ssl_verification` is not a bool.
        ValueError: The apikey, client_id, and/or client_secret are not valid for IAM token requests.
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
        # Check the type of `disable_ssl_verification`. Must be a bool.
        if not isinstance(disable_ssl_verification, bool):
            raise TypeError('disable_ssl_verification must be a bool')

        self.token_manager = IAMTokenManager(
            apikey,
            url=url,
            client_id=client_id,
            client_secret=client_secret,
            disable_ssl_verification=disable_ssl_verification,
            headers=headers,
            proxies=proxies,
            scope=scope,
        )

        self.validate()

    def authentication_type(self) -> str:
        """Returns this authenticator's type ('iam')."""
        return Authenticator.AUTHTYPE_IAM

    def validate(self) -> None:
        """Validates the apikey, client_id, and client_secret for IAM token requests.

        Ensure the apikey is not none, and has no bad characters. Additionally, ensure the
        both the client_id and client_secret are both set if either of them are defined.

        Raises:
            ValueError: The apikey, client_id, and/or client_secret are not valid for IAM token requests.
        """
        super().validate()

        if self.token_manager.apikey is None:
            raise ValueError('The apikey shouldn\'t be None.')

        if has_bad_first_or_last_char(self.token_manager.apikey):
            raise ValueError(
                'The apikey shouldn\'t start or end with curly brackets or quotes. '
                'Please remove any surrounding {, }, or \" characters.'
            )
