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

from typing import Optional

from requests import Request

from ..token_managers.vpc_instance_token_manager import VPCInstanceTokenManager
from .authenticator import Authenticator


class VPCInstanceAuthenticator(Authenticator):
    """VPCInstanceAuthenticator implements an authentication scheme in which it
       retrieves an "instance identity token" and exchanges that
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
            At most one of iamProfileCrn or iamProfileId may be specified. If neither one is specified,
            then the default IAM profile defined for the compute resource will be used. Defaults to None.
        url (str, optional):
            The VPC Instance Metadata Service's base endpoint URL. Defaults to 'http://169.254.169.254'.

    Attributes:
        iam_profile_crn (str, optional): The CRN of the linked trusted IAM profile.
        iam_profile_id (str, optional): The ID of the linked trusted IAM profile.
        url (str, optional): The VPC Instance Metadata Service's base endpoint URL.
    """

    DEFAULT_IMS_ENDPOINT = 'http://169.254.169.254'

    def __init__(
        self, iam_profile_crn: Optional[str] = None, iam_profile_id: Optional[str] = None, url: Optional[str] = None
    ) -> None:
        if not url:
            url = self.DEFAULT_IMS_ENDPOINT

        self.token_manager = VPCInstanceTokenManager(
            url=url, iam_profile_crn=iam_profile_crn, iam_profile_id=iam_profile_id
        )

        self.validate()

    def authentication_type(self) -> str:
        """Returns this authenticator's type ('VPC')."""
        return Authenticator.AUTHTYPE_VPC

    def validate(self) -> None:
        super().validate()

        if self.token_manager.iam_profile_crn and self.token_manager.iam_profile_id:
            raise ValueError('At most one of "iam_profile_id" or "iam_profile_crn" may be specified.')

    def authenticate(self, req: Request) -> None:
        """Adds IAM authentication information to the request.

        The IAM access token will be added to the request's headers in the form:

            Authorization: Bearer <bearer-token>

        Args:
            req: The request to add IAM authentication information too. Must contain a key to a dictionary
            called headers.
        """
        headers = req.get('headers')
        bearer_token = self.token_manager.get_token()
        headers['Authorization'] = 'Bearer {0}'.format(bearer_token)

    def set_iam_profile_crn(self, iam_profile_crn: str) -> None:
        """Sets CRN of the IAM profile.

        Args:
            iam_profile_crn (str): the CRN of the linked trusted IAM profile to be used as
                             the identity of the compute resource.

        Raises:
            ValueError: At most one of iam_profile_crn or iam_profile_id may be specified.
                        If neither one is specified, then the default IAM profile defined
                        for the compute resource will be used.
        """
        self.token_manager.set_iam_profile_crn(iam_profile_crn)
        self.validate()

    def set_iam_profile_id(self, iam_profile_id: str) -> None:
        """Sets the ID of the IAM profile.

        Args:
            iam_profile_id (str): id of the linked trusted IAM profile to be used when obtaining
                            the IAM access token

        Raises:
            ValueError: At most one of iam_profile_crn or iam_profile_id may be specified.
                        If neither one is specified, then the default IAM profile defined
                        for the compute resource will be used.
        """
        self.token_manager.set_iam_profile_id(iam_profile_id)
        self.validate()
