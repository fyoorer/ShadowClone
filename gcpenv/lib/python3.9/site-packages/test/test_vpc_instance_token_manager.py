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

# pylint: disable=missing-docstring
import json
import logging

import pytest
import responses

from ibm_cloud_sdk_core import ApiException, VPCInstanceTokenManager


# pylint: disable=line-too-long
TEST_ACCESS_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImhlbGxvIiwicm9sZSI6InVzZXIiLCJwZXJtaXNzaW9ucyI6WyJhZG1pbmlzdHJhdG9yIiwiZGVwbG95bWVudF9hZG1pbiJdLCJzdWIiOiJoZWxsbyIsImlzcyI6IkpvaG4iLCJhdWQiOiJEU1giLCJ1aWQiOiI5OTkiLCJpYXQiOjE1NjAyNzcwNTEsImV4cCI6MTU2MDI4MTgxOSwianRpIjoiMDRkMjBiMjUtZWUyZC00MDBmLTg2MjMtOGNkODA3MGI1NDY4In0.cIodB4I6CCcX8vfIImz7Cytux3GpWyObt9Gkur5g1QI'
TEST_TOKEN = 'abc123'
TEST_IAM_TOKEN = 'iam-abc123'
TEST_IAM_PROFILE_CRN = 'crn:iam-profile:123'
TEST_IAM_PROFILE_ID = 'iam-id-123'


def test_constructor():
    token_manager = VPCInstanceTokenManager(
        iam_profile_crn=TEST_IAM_PROFILE_CRN,
    )

    assert token_manager.iam_profile_crn is TEST_IAM_PROFILE_CRN
    assert token_manager.iam_profile_id is None
    assert token_manager.access_token is None


def test_setters():
    token_manager = VPCInstanceTokenManager(
        iam_profile_crn=TEST_IAM_PROFILE_CRN,
    )

    assert token_manager.iam_profile_crn is TEST_IAM_PROFILE_CRN
    assert token_manager.iam_profile_id is None
    assert token_manager.access_token is None

    token_manager.set_iam_profile_crn(None)
    assert token_manager.iam_profile_crn is None

    token_manager.set_iam_profile_id(TEST_IAM_PROFILE_ID)
    assert token_manager.iam_profile_id == TEST_IAM_PROFILE_ID


@responses.activate
def test_retrieve_instance_identity_token(caplog):
    caplog.set_level(logging.DEBUG)

    token_manager = VPCInstanceTokenManager(
        iam_profile_crn=TEST_IAM_PROFILE_CRN,
        url='http://someurl.com',
    )

    response = {
        'access_token': TEST_TOKEN,
    }

    responses.add(responses.PUT, 'http://someurl.com/instance_identity/v1/token', body=json.dumps(response), status=200)

    ii_token = token_manager.retrieve_instance_identity_token()
    assert len(responses.calls) == 1
    assert responses.calls[0].request.headers['Content-Type'] == 'application/json'
    assert responses.calls[0].request.headers['Accept'] == 'application/json'
    assert responses.calls[0].request.headers['Metadata-Flavor'] == 'ibm'
    assert responses.calls[0].request.params['version'] == '2022-03-01'
    assert responses.calls[0].request.body == '{"expires_in": 300}'
    assert ii_token == TEST_TOKEN
    # Check the logs.
    # pylint: disable=line-too-long
    assert (
        caplog.record_tuples[0][2]
        == 'Invoking VPC \'create_access_token\' operation: http://someurl.com/instance_identity/v1/token'
    )
    assert caplog.record_tuples[1][2] == 'Returned from VPC \'create_access_token\' operation."'


@responses.activate
def test_retrieve_instance_identity_token_failed(caplog):
    caplog.set_level(logging.DEBUG)

    token_manager = VPCInstanceTokenManager(
        iam_profile_crn=TEST_IAM_PROFILE_CRN,
        url='http://someurl.com',
    )

    response = {
        'errors': ['Ooops'],
    }

    responses.add(responses.PUT, 'http://someurl.com/instance_identity/v1/token', body=json.dumps(response), status=400)

    with pytest.raises(ApiException):
        token_manager.retrieve_instance_identity_token()

    assert len(responses.calls) == 1
    # Check the logs.
    # pylint: disable=line-too-long
    assert (
        caplog.record_tuples[0][2]
        == 'Invoking VPC \'create_access_token\' operation: http://someurl.com/instance_identity/v1/token'
    )


@responses.activate
def test_request_token_with_crn(caplog):
    caplog.set_level(logging.DEBUG)

    token_manager = VPCInstanceTokenManager(
        iam_profile_crn=TEST_IAM_PROFILE_CRN,
    )

    # Mock the retrieve instance identity token method.
    def mock_retrieve_instance_identity_token():
        return TEST_TOKEN

    token_manager.retrieve_instance_identity_token = mock_retrieve_instance_identity_token

    response = {
        'access_token': TEST_IAM_TOKEN,
    }

    responses.add(
        responses.POST, 'http://169.254.169.254/instance_identity/v1/iam_token', body=json.dumps(response), status=200
    )

    response = token_manager.request_token()
    assert len(responses.calls) == 1
    assert responses.calls[0].request.headers['Content-Type'] == 'application/json'
    assert responses.calls[0].request.headers['Accept'] == 'application/json'
    assert responses.calls[0].request.headers['Authorization'] == 'Bearer ' + TEST_TOKEN
    assert responses.calls[0].request.body == '{"trusted_profile": {"crn": "crn:iam-profile:123"}}'
    assert responses.calls[0].request.params['version'] == '2022-03-01'
    # Check the logs.
    # pylint: disable=line-too-long
    assert (
        caplog.record_tuples[0][2]
        == 'Invoking VPC \'create_iam_token\' operation: http://169.254.169.254/instance_identity/v1/iam_token'
    )
    assert caplog.record_tuples[1][2] == 'Returned from VPC \'create_iam_token\' operation."'


@responses.activate
def test_request_token_with_id(caplog):
    caplog.set_level(logging.DEBUG)

    token_manager = VPCInstanceTokenManager(
        iam_profile_id=TEST_IAM_PROFILE_ID,
    )

    # Mock the retrieve instance identity token method.
    def mock_retrieve_instance_identity_token():
        return TEST_TOKEN

    token_manager.retrieve_instance_identity_token = mock_retrieve_instance_identity_token

    response = {
        'access_token': TEST_IAM_TOKEN,
    }

    responses.add(
        responses.POST, 'http://169.254.169.254/instance_identity/v1/iam_token', body=json.dumps(response), status=200
    )

    response = token_manager.request_token()
    assert len(responses.calls) == 1
    assert responses.calls[0].request.headers['Content-Type'] == 'application/json'
    assert responses.calls[0].request.headers['Accept'] == 'application/json'
    assert responses.calls[0].request.headers['Authorization'] == 'Bearer ' + TEST_TOKEN
    assert responses.calls[0].request.body == '{"trusted_profile": {"id": "iam-id-123"}}'
    assert responses.calls[0].request.params['version'] == '2022-03-01'
    # Check the logs.
    # pylint: disable=line-too-long
    assert (
        caplog.record_tuples[0][2]
        == 'Invoking VPC \'create_iam_token\' operation: http://169.254.169.254/instance_identity/v1/iam_token'
    )
    assert caplog.record_tuples[1][2] == 'Returned from VPC \'create_iam_token\' operation."'


@responses.activate
def test_request_token(caplog):
    caplog.set_level(logging.DEBUG)

    token_manager = VPCInstanceTokenManager()

    # Mock the retrieve instance identity token method.
    def mock_retrieve_instance_identity_token():
        return TEST_TOKEN

    token_manager.retrieve_instance_identity_token = mock_retrieve_instance_identity_token

    response = {
        'access_token': TEST_IAM_TOKEN,
    }

    responses.add(
        responses.POST, 'http://169.254.169.254/instance_identity/v1/iam_token', body=json.dumps(response), status=200
    )

    response = token_manager.request_token()
    assert len(responses.calls) == 1
    assert responses.calls[0].request.headers['Content-Type'] == 'application/json'
    assert responses.calls[0].request.headers['Accept'] == 'application/json'
    assert responses.calls[0].request.headers['Authorization'] == 'Bearer ' + TEST_TOKEN
    assert responses.calls[0].request.body is None
    assert responses.calls[0].request.params['version'] == '2022-03-01'
    # Check the logs.
    # pylint: disable=line-too-long
    assert (
        caplog.record_tuples[0][2]
        == 'Invoking VPC \'create_iam_token\' operation: http://169.254.169.254/instance_identity/v1/iam_token'
    )
    assert caplog.record_tuples[1][2] == 'Returned from VPC \'create_iam_token\' operation."'


@responses.activate
def test_request_token_failed(caplog):
    caplog.set_level(logging.DEBUG)

    token_manager = VPCInstanceTokenManager(
        iam_profile_id=TEST_IAM_PROFILE_ID,
    )

    # Mock the retrieve instance identity token method.
    def mock_retrieve_instance_identity_token():
        return TEST_TOKEN

    token_manager.retrieve_instance_identity_token = mock_retrieve_instance_identity_token

    response = {
        'errors': ['Ooops'],
    }

    responses.add(
        responses.POST, 'http://169.254.169.254/instance_identity/v1/iam_token', body=json.dumps(response), status=400
    )

    with pytest.raises(ApiException):
        token_manager.request_token()
    assert len(responses.calls) == 1
    # Check the logs.
    # pylint: disable=line-too-long
    assert (
        caplog.record_tuples[0][2]
        == 'Invoking VPC \'create_iam_token\' operation: http://169.254.169.254/instance_identity/v1/iam_token'
    )


@responses.activate
def test_access_token():
    token_manager = VPCInstanceTokenManager(
        iam_profile_id=TEST_IAM_PROFILE_ID,
    )

    response_ii = {
        'access_token': TEST_TOKEN,
    }
    response_iam = {
        'access_token': TEST_ACCESS_TOKEN,
    }

    responses.add(
        responses.PUT, 'http://169.254.169.254/instance_identity/v1/token', body=json.dumps(response_ii), status=200
    )
    responses.add(
        responses.POST,
        'http://169.254.169.254/instance_identity/v1/iam_token',
        body=json.dumps(response_iam),
        status=200,
    )

    assert token_manager.access_token is None
    assert token_manager.expire_time == 0
    assert token_manager.refresh_time == 0

    token_manager.get_token()
    assert token_manager.access_token == TEST_ACCESS_TOKEN
    assert token_manager.expire_time > 0
    assert token_manager.refresh_time > 0
