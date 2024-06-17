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

from http import HTTPStatus
from typing import Optional

from requests import Response


class ApiException(Exception):
    """Custom exception class for errors returned from operations.

    Args:
        code: HTTP status code of the error response.
        message: The error response body. Defaults to None.
        http_response: The HTTP response of the failed request. Defaults to None.

    Attributes:
        code (int): HTTP status code of the error response.
        message (str): The error response body.
        http_response (requests.Response): The HTTP response of the failed request.
        global_transaction_id (str, optional): Globally unique id the service endpoint has given a transaction.
    """

    def __init__(self, code: int, *, message: Optional[str] = None, http_response: Optional[Response] = None) -> None:
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.message = message
        self.code = code
        self.http_response = http_response
        self.global_transaction_id = None
        if http_response is not None:
            self.global_transaction_id = http_response.headers.get('X-Global-Transaction-ID')
            self.message = self.message if self.message else self._get_error_message(http_response)

    def __str__(self) -> str:
        msg = 'Error: ' + str(self.message) + ', Code: ' + str(self.code)
        if self.global_transaction_id is not None:
            msg += ' , X-global-transaction-id: ' + str(self.global_transaction_id)
        return msg

    @staticmethod
    def _get_error_message(response: Response) -> str:
        error_message = 'Unknown error'
        try:
            error_json = response.json(strict=False)
            if 'errors' in error_json:
                if isinstance(error_json['errors'], list):
                    err = error_json['errors'][0]
                    error_message = err.get('message')
            elif 'error' in error_json:
                error_message = error_json['error']
            elif 'message' in error_json:
                error_message = error_json['message']
            elif 'errorMessage' in error_json:
                error_message = error_json['errorMessage']
            elif response.status_code == 401:
                error_message = 'Unauthorized: Access is denied due to invalid credentials'
            else:
                error_message = HTTPStatus(response.status_code).phrase
            return error_message
        except:
            return response.text or error_message
