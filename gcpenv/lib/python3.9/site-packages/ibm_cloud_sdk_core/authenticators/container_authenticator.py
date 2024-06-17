# coding: utf-8

# Copyright 2021 IBM All Rights Reserved.
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

from .iam_request_based_authenticator import IAMRequestBasedAuthenticator
from ..token_managers.container_token_manager import ContainerTokenManager
from .authenticator import Authenticator


class ContainerAuthenticator(IAMRequestBasedAuthenticator):
    """ContainerAuthenticator implements an IAM-based authentication schema where by it
    retrieves a "compute resource token" from the local compute resource (VM)
    and uses that to obtain an IAM access token by invoking the IAM "get token" operation with grant-type=cr-token.
    The resulting IAM access token is then added to outbound requests in an Authorization header of the form:

        Authorization: Bearer <access-token>

    Args:
        cr_token_filename: The name of the file containing the injected CR token value
            (applies to IKS-managed compute resources). Defaults to "/var/run/secrets/tokens/vault-token".
        iam_profile_name: The name of the linked trusted IAM profile to be used when obtaining the IAM access token
            (a CR token might map to multiple IAM profiles).
            One of iam_profile_name or iam_profile_id must be specified.
            Defaults to None.
        iam_profile_id: The id of the linked trusted IAM profile to be used when obtaining the IAM access token
            (a CR token might map to multiple IAM profiles).
            One of iam_profile_name or iam_profile_id must be specified.
            Defaults to None.
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
            token_manager (ContainerTokenManager): Retrieves and manages IAM tokens
                from the endpoint specified by the url.

        Raises:
            TypeError: The `disable_ssl_verification` is not a bool.
            ValueError: Neither of iam_profile_name or iam_profile_idk are set,
            or client_id, and/or client_secret are not valid for IAM token requests.
    """

    def __init__(
        self,
        cr_token_filename: Optional[str] = None,
        iam_profile_name: Optional[str] = None,
        iam_profile_id: Optional[str] = None,
        url: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        disable_ssl_verification: bool = False,
        scope: Optional[str] = None,
        proxies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        # Check the type of `disable_ssl_verification`. Must be a bool.
        if not isinstance(disable_ssl_verification, bool):
            raise TypeError('disable_ssl_verification must be a bool')

        self.token_manager = ContainerTokenManager(
            cr_token_filename=cr_token_filename,
            iam_profile_name=iam_profile_name,
            iam_profile_id=iam_profile_id,
            url=url,
            client_id=client_id,
            client_secret=client_secret,
            disable_ssl_verification=disable_ssl_verification,
            scope=scope,
            proxies=proxies,
            headers=headers,
        )

        self.validate()

    def authentication_type(self) -> str:
        """Returns this authenticator's type ('container')."""
        return Authenticator.AUTHTYPE_CONTAINER

    def validate(self) -> None:
        """Validates the iam_profile_name, iam_profile_id, client_id, and client_secret for IAM token requests.

        Ensure that one of the iam_profile_name or iam_profile_id are specified. Additionally, ensure
        both of the client_id and client_secret are set if either of them are defined.

        Raises:
            ValueError: Neither of iam_profile_name or iam_profile_idk are set,
            or client_id, and/or client_secret are not valid for IAM token requests.
        """
        super().validate()

        if not self.token_manager.iam_profile_name and not self.token_manager.iam_profile_id:
            raise ValueError('At least one of iam_profile_name or iam_profile_id must be specified.')

    def set_cr_token_filename(self, cr_token_filename: str) -> None:
        """Set the location of the compute resource token on the local filesystem.

        Args:
            cr_token_filename: path to the compute resource token
        """
        self.token_manager.cr_token_filename = cr_token_filename

    def set_iam_profile_name(self, iam_profile_name: str) -> None:
        """Set the name of the IAM profile.

        Args:
            iam_profile_name: name of the linked trusted IAM profile to be used when obtaining the IAM access token

        Raises:
            ValueError: Neither of iam_profile_name or iam_profile_idk are set,
            or client_id, and/or client_secret are not valid for IAM token requests.
        """
        self.token_manager.iam_profile_name = iam_profile_name
        self.validate()

    def set_iam_profile_id(self, iam_profile_id: str) -> None:
        """Set the id of the IAM profile.

        Args:
            iam_profile_id: id of the linked trusted IAM profile to be used when obtaining the IAM access token

        Raises:
            ValueError: Neither of iam_profile_name or iam_profile_idk are set,
            or client_id, and/or client_secret are not valid for IAM token requests.
        """
        self.token_manager.iam_profile_id = iam_profile_id
        self.validate()
