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

import base64
from requests import Request

from .authenticator import Authenticator
from ..utils import has_bad_first_or_last_char


class BasicAuthenticator(Authenticator):
    """The BasicAuthenticator is used to add basic authentication information to requests.

    Basic Authorization will be sent as an Authorization header in the form:

        Authorization: Basic <encoded username and password>

    Args:
        username: User-supplied username for basic auth.
        password: User-supplied password for basic auth.

    Raises:
        ValueError: The username or password is not specified or contains invalid characters.
    """

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.validate()
        self.authorization_header = self.__construct_basic_auth_header()

    def authentication_type(self) -> str:
        """Returns this authenticator's type ('basic')."""
        return Authenticator.AUTHTYPE_BASIC

    def validate(self) -> None:
        """Validate username and password.

        Ensure the username and password are valid for service operations.

        Raises:
            ValueError: The username and/or password is not valid for service operations.
        """
        if self.username is None or self.password is None:
            raise ValueError('The username and password shouldn\'t be None.')

        if has_bad_first_or_last_char(self.username) or has_bad_first_or_last_char(self.password):
            raise ValueError(
                'The username and password shouldn\'t start or end with curly brackets or quotes. '
                'Please remove any surrounding {, }, or \" characters.'
            )

    def __construct_basic_auth_header(self) -> str:
        authstring = "{0}:{1}".format(self.username, self.password)
        base64_authorization = base64.b64encode(authstring.encode('utf-8')).decode('utf-8')
        return 'Basic {0}'.format(base64_authorization)

    def authenticate(self, req: Request) -> None:
        """Add basic authentication information to a request.

        Basic Authorization will be added to the request's headers in the form:

            Authorization: Basic <encoded username and password>

        Args:
            req: The request to add basic auth information too. Must contain a key to a dictionary
            called headers.
        """
        headers = req.get('headers')
        headers['Authorization'] = self.authorization_header
