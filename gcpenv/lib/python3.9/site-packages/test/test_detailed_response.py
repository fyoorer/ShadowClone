# coding=utf-8
# pylint: disable=missing-docstring
import json

import responses
import requests

from ibm_cloud_sdk_core import DetailedResponse


def clean(val):
    """Eliminate all whitespace and convert single to double quotes"""
    return val.translate(str.maketrans('', '', ' \n\t\r')).replace("'", "\"")


@responses.activate
def test_detailed_response_dict():
    responses.add(
        responses.GET,
        'https://test.com',
        status=200,
        body=json.dumps({'foobar': 'baz'}),
        content_type='application/json',
    )

    mock_response = requests.get('https://test.com', timeout=None)
    detailed_response = DetailedResponse(
        response=mock_response.json(), headers=mock_response.headers, status_code=mock_response.status_code
    )
    assert detailed_response is not None
    assert detailed_response.get_result() == {'foobar': 'baz'}
    assert detailed_response.get_headers() == {'Content-Type': 'application/json'}
    assert detailed_response.get_status_code() == 200

    response_str = clean(str(detailed_response))
    assert clean(str(detailed_response.get_result())) in response_str
    # assert clean(str(detailed_response.get_headers())) in response_str
    assert clean(str(detailed_response.get_status_code())) in response_str


@responses.activate
def test_detailed_response_list():
    responses.add(
        responses.GET,
        'https://test.com',
        status=200,
        body=json.dumps(['foobar', 'baz']),
        content_type='application/json',
    )

    mock_response = requests.get('https://test.com', timeout=None)
    detailed_response = DetailedResponse(
        response=mock_response.json(), headers=mock_response.headers, status_code=mock_response.status_code
    )
    assert detailed_response is not None
    assert detailed_response.get_result() == ['foobar', 'baz']
    assert detailed_response.get_headers() == {'Content-Type': 'application/json'}
    assert detailed_response.get_status_code() == 200

    response_str = clean(str(detailed_response))
    assert clean(str(detailed_response.get_result())) in response_str
    # assert clean(str(detailed_response.get_headers())) in response_str
    assert clean(str(detailed_response.get_status_code())) in response_str
