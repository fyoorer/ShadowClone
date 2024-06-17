# pylint: disable=missing-docstring
import os

from ibm_cloud_sdk_core import get_authenticator_from_environment

# Note: Only the unit tests are run by default.
#
# In order to test with a live IAM server, create file "iamtest.env" in the project root.
# It should look like this:
#
# 	IAMTEST1_AUTH_URL=<url>   e.g. https://iam.cloud.ibm.com
# 	IAMTEST1_AUTH_TYPE=iam
# 	IAMTEST1_APIKEY=<apikey>
#
# Then run this command:
# pytest test_integration/test_iam_authenticator_integration.py


def test_iam_authenticator():
    os.environ['IBM_CREDENTIALS_FILE'] = 'iamtest.env'

    authenticator = get_authenticator_from_environment('iamtest1')
    assert authenticator is not None

    request = {'headers': {}}
    authenticator.authenticate(request)
    assert request['headers']['Authorization'] is not None
    assert 'Bearer' in request['headers']['Authorization']
