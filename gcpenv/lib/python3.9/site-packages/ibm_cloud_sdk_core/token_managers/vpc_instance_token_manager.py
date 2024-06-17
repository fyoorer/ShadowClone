# coding: utf-8

# Copyright 2021, 2023 IBM All Rights Reserved.
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
import logging
from typing import Optional

from .jwt_token_manager import JWTTokenManager


logger = logging.getLogger(__name__)


class VPCInstanceTokenManager(JWTTokenManager):
    """The VPCInstanceTokenManager retrieves an "instance identity token" and exchanges that
       for an IAM access token using the VPC Instance Metadata Service API which is available
       on the local compute resource (VM).
       The instance identity token is similar to an IAM apikey, except that it is managed
       automatically by the compute resource provider (VPC).
       The resulting IAM access token is then added to outbound requests in an Authorization header of the form:

           Authorization: Bearer <access-token>

    Keyword Arguments:
        iam_profile_crn (str, optional):
            The CRN of the linked trusted IAM profile to be used as the identity of the compute resource.
            At most one of iam_profile_crn or iam_profile_id may be specified. If neither one is specified,
            then the default IAM profile defined for the compute resource will be used. Defaults to None.
        iam_profile_id (str, optional):
            The ID of the linked trusted IAM profile to be used when obtaining the IAM access token.
            At most one of iam_profile_crn or iam_profile_id may be specified. If neither one is specified,
            then the default IAM profile defined for the compute resource will be used. Defaults to None.
        url (str, optional):
            The VPC Instance Metadata Service's base endpoint URL. Defaults to 'http://169.254.169.254'.

    Attributes:
        iam_profile_crn (str, optional): The CRN of the linked trusted IAM profile.
        iam_profile_id (str, optional): The ID of the linked trusted IAM profile.
        url (str, optional): The VPC Instance Metadata Service's base endpoint URL.
    """

    METADATA_SERVICE_VERSION = '2022-03-01'
    DEFAULT_IMS_ENDPOINT = 'http://169.254.169.254'
    TOKEN_NAME = 'access_token'

    def __init__(
        self, iam_profile_crn: Optional[str] = None, iam_profile_id: Optional[str] = None, url: Optional[str] = None
    ) -> None:
        if not url:
            url = self.DEFAULT_IMS_ENDPOINT

        super().__init__(url, token_name=self.TOKEN_NAME)

        self.iam_profile_crn = iam_profile_crn
        self.iam_profile_id = iam_profile_id

    def request_token(self) -> dict:
        """RequestToken will use the VPC Instance Metadata Service to
           (1) retrieve a fresh instance identity token and then
           (2) exchange that for an IAM access token.

        Returns:
            A dictionary containing the bearer token to be subsequently used service requests.
        """

        # Retrieve the Instance Identity Token first.
        instance_identity_token = self.retrieve_instance_identity_token()

        url = self.url + '/instance_identity/v1/iam_token'

        request_payload = None
        if self.iam_profile_crn:
            request_payload = {'trusted_profile': {'crn': self.iam_profile_crn}}
        if self.iam_profile_id:
            request_payload = {'trusted_profile': {'id': self.iam_profile_id}}

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + instance_identity_token,
        }

        logger.debug('Invoking VPC \'create_iam_token\' operation: %s', url)
        response = self._request(
            method='POST',
            url=url,
            headers=headers,
            params={'version': self.METADATA_SERVICE_VERSION},
            data=json.dumps(request_payload) if request_payload else None,
        )
        logger.debug('Returned from VPC \'create_iam_token\' operation."')

        return response

    def set_iam_profile_crn(self, iam_profile_crn: str) -> None:
        """Sets the CRN of the IAM profile.

        Args:
            iam_profile_crn (str): the CRN of the linked trusted IAM profile to be used as
                             the identity of the compute resource.
        """
        self.iam_profile_crn = iam_profile_crn

    def set_iam_profile_id(self, iam_profile_id: str) -> None:
        """Sets the ID of the IAM profile.

        Args:
            iam_profile_id (str): id of the linked trusted IAM profile to be used when obtaining
                            the IAM access token
        """
        self.iam_profile_id = iam_profile_id

    def retrieve_instance_identity_token(self) -> str:
        """Retrieves the local compute resource's instance identity token using
           the "create_access_token" operation of the local VPC Instance Metadata Service API.

        Returns:
            The retrieved instance identity token string.
        """

        url = self.url + '/instance_identity/v1/token'

        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
            'Metadata-Flavor': 'ibm',
        }

        request_body = {'expires_in': 300}

        logger.debug('Invoking VPC \'create_access_token\' operation: %s', url)
        response = self._request(
            method='PUT',
            url=url,
            headers=headers,
            params={'version': self.METADATA_SERVICE_VERSION},
            data=json.dumps(request_body),
        )
        logger.debug('Returned from VPC \'create_access_token\' operation."')

        return response['access_token']
