# coding: utf-8

# Copyright 2019, 2020 IBM All Rights Reserved.
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

from abc import ABC
from typing import Optional

import jwt
import requests

from .token_manager import TokenManager
from ..api_exception import ApiException


class JWTTokenManager(TokenManager, ABC):
    """An abstract class to contain functionality for parsing, storing, and requesting JWT tokens.

    get_token will retrieve a new token from the url in case the that there is no existing token,
    or the previous token has expired. Child classes will implement request_token, which will do
    the actual acquisition of a new token.

    Args:
        url: The url to request tokens from.

    Keyword Args:
        disable_ssl_verification: A flag that indicates whether verification of
            the server's SSL certificate should be disabled or not. Defaults to False.
        token_name: The key that maps to the token in the dictionary returned from request_token. Defaults to None.

    Attributes:
        url (str): The url to request tokens from.
        disable_ssl_verification (bool): A flag that indicates whether verification of
        the server's SSL certificate should be disabled or not.
        token_name (str): The key used of the token in the dict returned from request_token.
        token_info (dict): The most token_response from request_token.
    """

    def __init__(self, url: str, *, disable_ssl_verification: bool = False, token_name: Optional[str] = None):
        super().__init__(url, disable_ssl_verification=disable_ssl_verification)
        self.token_name = token_name
        self.token_info = {}

    def _save_token_info(self, token_response: dict) -> None:
        """
        Decode the access token and save the response from the JWT service to the object's state
        Refresh time is set to approximately 80% of the token's TTL to ensure that
        the token refresh completes before the current token expires.
        Parameters
        ----------
        token_response : dict
            Response from token service
        """
        self.token_info = token_response
        self.access_token = token_response.get(self.token_name)

        # The time of expiration is found by decoding the JWT access token
        decoded_response = jwt.decode(self.access_token, algorithms=["RS256"], options={"verify_signature": False})
        # exp is the time of expire and iat is the time of token retrieval
        exp = decoded_response.get('exp')
        iat = decoded_response.get('iat')

        self.expire_time = exp
        buffer = (exp - iat) * 0.2
        self.refresh_time = self.expire_time - buffer

    def _request(self, method, url, *, headers=None, params=None, data=None, auth_tuple=None, **kwargs) -> dict:
        kwargs = dict({"timeout": 60}, **kwargs)
        kwargs = dict(kwargs, **self.http_config)

        if self.disable_ssl_verification:
            kwargs['verify'] = False

        response = requests.request(
            method=method, url=url, headers=headers, params=params, data=data, auth=auth_tuple, **kwargs
        )
        if 200 <= response.status_code <= 299:
            return response.json()

        raise ApiException(response.status_code, http_response=response)
