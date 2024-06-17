#
# (C) Copyright Cloudlab URV 2020
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import re
import os
import shutil
import time
import logging
from requests.exceptions import SSLError as TooManyConnectionsError
from io import BytesIO
from google.api_core import exceptions as google_exceptions
from google.cloud import storage
from google.cloud.exceptions import NotFound
from lithops.constants import STORAGE_CLI_MSG
from lithops.storage.utils import StorageNoSuchKeyError

logger = logging.getLogger(__name__)

TIMEOUT = 5

class GCPStorageBackend:
    def __init__(self, gcp_storage_config):
        logger.debug("Creating GCP Storage client")
        self.credentials_path = gcp_storage_config.get('credentials_path')
        if self.credentials_path and os.path.isfile(self.credentials_path): 
            logger.debug(f'Getting GCP credentials from {self.credentials_path}')
            self.client = storage.Client.from_service_account_json(self.credentials_path)
        else:
            logger.debug(f'Getting GCP credentials from the environment')
            self.client = storage.Client()
        msg = STORAGE_CLI_MSG.format('Google Cloud Storage')
        logger.info("{}".format(msg))

    def get_client(self):
        return self.client

    def put_object(self, bucket_name, key, data):
        done = False
        while not done:
            try:
                bucket = self.client.get_bucket(bucket_name, timeout=TIMEOUT)
                blob = bucket.blob(blob_name=key)
                if hasattr(data, 'read'):
                    blob.upload_from_file(file_obj=data)
                else:
                    blob.upload_from_string(data=data)
                done = True
            except TooManyConnectionsError:
                time.sleep(0.1)
            except google_exceptions.NotFound:
                raise StorageNoSuchKeyError(bucket=bucket_name, key=key)

    def get_object(self, bucket_name, key, stream=False, extra_get_args={}):
        try:
            bucket = self.client.get_bucket(bucket_name, timeout=TIMEOUT)
            blob = bucket.blob(blob_name=key)
        except google_exceptions.NotFound:
            raise StorageNoSuchKeyError(bucket_name, key)

        if not blob.exists():
            raise StorageNoSuchKeyError(bucket_name, key)

        if extra_get_args and 'Range' in extra_get_args:
            start, end = re.findall(r'\d+', extra_get_args['Range'])
            start = int(start)
            end = int(end)
        else:
            start, end = None, None

        if stream:
            stream = BytesIO()
            # Download object to bytes buffer
            blob.download_to_file(stream, start=start, end=end)
            stream.seek(0)  # Retrun to the initial buffer position
            return stream
        else:
            return blob.download_as_string(start=start, end=end)

    def upload_file(self, file_name, bucket, key=None, extra_args={}):
        """Upload a file

        :param file_name: File to upload
        :param bucket: Bucket to upload to
        :param key: object name. If not specified then file_name is used
        :return: True if file was uploaded, else False
        """
        # If S3 key was not specified, use file_name
        if key is None:
            key = os.path.basename(file_name)

        # Upload the file
        try:
            with open(file_name, 'rb') as in_file:
                self.put_object(bucket, key, in_file)
        except Exception as e:
            logging.error(e)
            return False
        return True

    def download_file(self, bucket, key, file_name=None, extra_args={}):
        """Download a file

        :param bucket: Bucket to download from
        :param key: object name. If not specified then file_name is used
        :param file_name: File to upload
        :return: True if file was downloaded, else False
        """
        # If file_name was not specified, use S3 key
        if file_name is None:
            file_name = key

        # Download the file
        try:
            dirname = os.path.dirname(file_name)
            if dirname and not os.path.exists(dirname):
                os.makedirs(dirname)
            with open(file_name, 'wb') as out:
                data_stream = self.get_object(bucket, key, stream=True)
                shutil.copyfileobj(data_stream, out)
        except Exception as e:
            logging.error(e)
            return False
        return True

    def head_object(self, bucket_name, key):
        try:
            bucket = self.client.get_bucket(bucket_name, timeout=TIMEOUT)
            blob = bucket.get_blob(blob_name=key)
        except google_exceptions.NotFound:
            raise StorageNoSuchKeyError(bucket_name, key)

        if blob is None:
            raise StorageNoSuchKeyError(bucket_name, key)

        response = {
            'LastModified': blob.updated,
            'ETag': blob.etag,
            'content-type': blob.content_type,
            'content-length': str(blob.size)
        }
        return response

    def delete_object(self, bucket_name, key):
        try:
            bucket = self.client.get_bucket(bucket_name, timeout=TIMEOUT)
        except google_exceptions.NotFound:
            raise StorageNoSuchKeyError(bucket_name, key)
        blob = bucket.get_blob(blob_name=key)
        if blob is None:
            raise StorageNoSuchKeyError(bucket_name, key)
        blob.delete()

    def delete_objects(self, bucket_name, key_list):
        bucket = self.client.get_bucket(bucket_name, timeout=TIMEOUT)
        try:
            bucket.delete_blobs(blobs=key_list)
        except google_exceptions.NotFound:
            pass

    def head_bucket(self, bucket_name):
        bucket = self.client.get_bucket(bucket_name, timeout=TIMEOUT)
        response = {
            'ResponseMetadata':
                {'HTTPStatusCode': 200, 
                'HTTPHeaders': {'content-type': 'application/xml', 
                                'server': 'GoogleStorage'}
                }
        }
        response['ResponseMetadata']['HTTPHeaders'].update(bucket._properties)
        return response

    def list_objects(self, bucket_name, prefix=None, match_pattern = None):
        try:
            bucket = self.client.get_bucket(bucket_name, timeout=TIMEOUT)
            page = bucket.list_blobs(prefix=prefix)
        except google_exceptions.ClientError:
            raise StorageNoSuchKeyError(bucket_name, '')
        return [{'Key': blob.name, 'Size': blob.size, 'LastModified': blob.updated } for blob in page]

    def list_keys(self, bucket_name, prefix=None):
        try:
            bucket = self.client.get_bucket(bucket_name, timeout=TIMEOUT)
            page = bucket.list_blobs(prefix=prefix)
        except google_exceptions.ClientError:
            raise StorageNoSuchKeyError(bucket_name, '')
        return [blob.name for blob in page]
