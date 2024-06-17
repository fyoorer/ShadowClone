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

import logging
from typing import Dict, Optional

from .iam_request_based_token_manager import IAMRequestBasedTokenManager


logger = logging.getLogger(__name__)


class ContainerTokenManager(IAMRequestBasedTokenManager):
    """The ContainerTokenManager takes a compute resource token and performs the necessary interactions with
    the IAM token service to obtain and store a suitable bearer token. Additionally, the ContainerTokenManager
    will retrieve bearer tokens via basic auth using a supplied client_id and client_secret pair.

    If the current stored bearer token has expired a new bearer token will be retrieved.

    Attributes:
        cr_token_filename(str): The name of the file containing the injected CR token value
            (applies to IKS-managed compute resources).
        iam_profile_name (str): The name of the linked trusted IAM profile to be used when obtaining the
            IAM access token (a CR token might map to multiple IAM profiles).
            One of iam_profile_name or iam_profile_id must be specified.
        iam_profile_id (str): The id of the linked trusted IAM profile to be used when obtaining the IAM access token
            (a CR token might map to multiple IAM profiles).
            One of iam_profile_name or iam_profile_id must be specified.
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
        cr_token_filename: The name of the file containing the injected CR token value
            (applies to IKS-managed compute resources). Defaults to "/var/run/secrets/tokens/vault-token".
        iam_profile_name: The name of the linked trusted IAM profile to be used when obtaining the IAM access token
            (a CR token might map to multiple IAM profiles).
            One of iam_profile_name or iam_profile_id must be specified.
            Defaults to None.
        iam_profile_id: The id of the linked trusted IAM profile to be used when obtaining the IAM access token
            (a CR token might map to multiple IAM profiles).
            One of iam_profile_name or iam_prfoile_id must be specified.
            Defaults to None.
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

    DEFAULT_CR_TOKEN_FILENAME1 = '/var/run/secrets/tokens/vault-token'
    DEFAULT_CR_TOKEN_FILENAME2 = '/var/run/secrets/tokens/sa-token'

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
        super().__init__(
            url=url,
            client_id=client_id,
            client_secret=client_secret,
            disable_ssl_verification=disable_ssl_verification,
            headers=headers,
            proxies=proxies,
            scope=scope,
        )

        self.cr_token_filename = cr_token_filename
        self.iam_profile_name = iam_profile_name
        self.iam_profile_id = iam_profile_id

        self.request_payload['grant_type'] = 'urn:ibm:params:oauth:grant-type:cr-token'

    def retrieve_cr_token(self) -> str:
        """Retrieves the CR token for the current compute resource by reading it from the local file system.

        Raises:
            Exception: Error retrieving the compute resource token.

        Returns:
            A string which contains the compute resource token.
        """
        try:
            cr_token = None
            if self.cr_token_filename:
                # If the user specified a filename, then use that.
                cr_token = self.read_file(self.cr_token_filename)
            else:
                # If the user didn't specify a filename, then try our two defaults.
                try:
                    cr_token = self.read_file(self.DEFAULT_CR_TOKEN_FILENAME1)
                except:
                    cr_token = self.read_file(self.DEFAULT_CR_TOKEN_FILENAME2)
            return cr_token
        except Exception as ex:
            # pylint: disable=broad-exception-raised
            raise Exception('Unable to retrieve the CR token: {}'.format(ex)) from None

    def request_token(self) -> dict:
        """Retrieves a CR token value from the current compute resource,
        then uses that to obtain a new IAM access token from the IAM token server.

        Returns:
             A dictionary containing the bearer token to be subsequently used service requests.
        """

        # Set the request payload.
        self.request_payload['cr_token'] = self.retrieve_cr_token()

        if self.iam_profile_id:
            self.request_payload['profile_id'] = self.iam_profile_id
        if self.iam_profile_name:
            self.request_payload['profile_name'] = self.iam_profile_name

        return super().request_token()

    def set_cr_token_filename(self, cr_token_filename: str) -> None:
        """Set the location of the compute resource token on the local filesystem.

        Args:
            cr_token_filename: path to the compute resource token
        """
        self.cr_token_filename = cr_token_filename

    def set_iam_profile_name(self, iam_profile_name: str) -> None:
        """Set the name of the IAM profile.

        Args:
            iam_profile_name: name of the linked trusted IAM profile to be used when obtaining the IAM access token
        """
        self.iam_profile_name = iam_profile_name

    def set_iam_profile_id(self, iam_profile_id: str) -> None:
        """Set the id of the IAM profile.

        Args:
            iam_profile_id: id of the linked trusted IAM profile to be used when obtaining the IAM access token
        """
        self.iam_profile_id = iam_profile_id

    def read_file(self, filename: str) -> str:
        """Read in the specified file and return the contents as a string.
        Args:
            filename: the name of the file to read
        Returns:
            The contents of the file as a string.
        Raises:
            Exception: An error occured reading the file.
        """
        try:
            logger.debug('Attempting to read CR token from file: %s', filename)
            with open(filename, 'r', encoding='utf-8') as file:
                cr_token = file.read()
            logger.debug('Successfully read CR token from file: %s', filename)
            return cr_token
        except Exception as ex:
            # pylint: disable=broad-exception-raised
            raise Exception('Error reading CR token from file {}: {}'.format(filename, ex)) from None
