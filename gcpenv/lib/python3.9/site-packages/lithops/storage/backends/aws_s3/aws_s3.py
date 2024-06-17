#
# (C) Copyright Cloudlab URV 2020
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import logging
import boto3
from botocore import UNSIGNED
from botocore.config import Config
import botocore
from lithops.storage.utils import StorageNoSuchKeyError
from lithops.utils import sizeof_fmt
from lithops.constants import STORAGE_CLI_MSG
from lithops.libs.globber import match

logger = logging.getLogger(__name__)

OBJ_REQ_RETRIES = 5
CONN_READ_TIMEOUT = 10


class S3Backend:
    def __init__(self, s3_config):
        logger.debug("Creating S3 client")
        self.s3_config = s3_config
        self.user_agent = s3_config['user_agent']
        self.region_name = s3_config.get('region_name')
        self.access_key_id = s3_config.get('access_key_id')
        self.secret_access_key = s3_config.get('secret_access_key')
        self.session_token = s3_config.get('session_token')

        if self.access_key_id and self.secret_access_key:
            client_config = Config(
                max_pool_connections=128,
                user_agent_extra=self.user_agent,
                connect_timeout=CONN_READ_TIMEOUT,
                read_timeout=CONN_READ_TIMEOUT,
                retries={'max_attempts': OBJ_REQ_RETRIES}
            )
            self.s3_client = boto3.client(
                's3', aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                aws_session_token=self.session_token,
                config=client_config,
                region_name=self.region_name
            )
        else:
            client_config = Config(
                signature_version=UNSIGNED,
                user_agent_extra=self.user_agent
            )
            self.s3_client = boto3.client('s3', config=client_config)

        msg = STORAGE_CLI_MSG.format('S3')
        logger.info(f"{msg} - Region: {self.region_name}")

    def get_client(self):
        '''
        Get boto3 client.
        :return: boto3 client
        '''
        return self.s3_client

    def put_object(self, bucket_name, key, data):
        '''
        Put an object in COS. Override the object if the key already exists.
        :param key: key of the object.
        :param data: data of the object
        :type data: str/bytes
        :return: None
        '''
        try:
            res = self.s3_client.put_object(Bucket=bucket_name, Key=key, Body=data)
            status = 'OK' if res['ResponseMetadata']['HTTPStatusCode'] == 200 else 'Error'
            try:
                logger.debug('PUT Object {} - Size: {} - {}'.format(key, sizeof_fmt(len(data)), status))
            except Exception:
                logger.debug('PUT Object {} {}'.format(key, status))
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                raise StorageNoSuchKeyError(bucket_name, key)
            else:
                raise e

    def get_object(self, bucket_name, key, stream=False, extra_get_args={}):
        '''
        Get object from COS with a key. Throws StorageNoSuchKeyError if the given key does not exist.
        :param key: key of the object
        :return: Data of the object
        :rtype: str/bytes
        '''
        try:
            r = self.s3_client.get_object(Bucket=bucket_name, Key=key, **extra_get_args)
            if stream:
                data = r['Body']
            else:
                data = r['Body'].read()
            return data
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                raise StorageNoSuchKeyError(bucket_name, key)
            else:
                raise e

    def upload_file(self, file_name, bucket, key=None, extra_args={}):
        """Upload a file to an S3 bucket

        :param file_name: File to upload
        :param bucket: Bucket to upload to
        :param key: S3 object name. If not specified then file_name is used
        :return: True if file was uploaded, else False
        """
        # If S3 key was not specified, use file_name
        if key is None:
            key = os.path.basename(file_name)

        # Upload the file
        try:
            self.s3_client.upload_file(file_name, bucket, key, ExtraArgs=extra_args)
        except botocore.exceptions.ClientError as e:
            logging.error(e)
            return False
        return True

    def download_file(self, bucket, key, file_name=None, extra_args={}):
        """Download a file from an S3 bucket

        :param bucket: Bucket to download from
        :param key: S3 object name. If not specified then file_name is used
        :param file_name: File to upload
        :return: True if file was downloaded, else False
        """
        # If file_name was not specified, use S3 key
        if file_name is None:
            file_name = key

        # Download the file
        try:
            self.s3_client.download_file(bucket, key, file_name, ExtraArgs=extra_args)
        except botocore.exceptions.ClientError as e:
            logging.error(e)
            return False
        return True

    def head_object(self, bucket_name, key):
        '''
        Head object from COS with a key. Throws StorageNoSuchKeyError if the given key does not exist.
        :param key: key of the object
        :return: Data of the object
        :rtype: str/bytes
        '''
        try:
            metadata = self.s3_client.head_object(Bucket=bucket_name, Key=key)
            return metadata['ResponseMetadata']['HTTPHeaders']
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == '404':
                raise StorageNoSuchKeyError(bucket_name, key)
            else:
                raise e

    def delete_object(self, bucket_name, key):
        '''
        Delete an object from storage.
        :param bucket: bucket name
        :param key: data key
        '''
        return self.s3_client.delete_object(Bucket=bucket_name, Key=key)

    def delete_objects(self, bucket_name, key_list):
        '''
        Delete a list of objects from storage.
        :param bucket: bucket name
        :param key_list: list of keys
        '''
        result = []
        max_keys_num = 1000
        for i in range(0, len(key_list), max_keys_num):
            delete_keys = {'Objects': []}
            delete_keys['Objects'] = [{'Key': k} for k in key_list[i:i + max_keys_num]]
            result.append(self.s3_client.delete_objects(Bucket=bucket_name, Delete=delete_keys))
        return result

    def head_bucket(self, bucket_name):
        '''
        Head bucket from COS with a name. Throws StorageNoSuchKeyError if the given bucket does not exist.
        :param bucket_name: name of the bucket
        :return: Metadata of the bucket
        :rtype: str/bytes
        '''
        try:
            return self.s3_client.head_bucket(Bucket=bucket_name)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == '404':
                raise StorageNoSuchKeyError(bucket_name, '')
            else:
                raise e

    def list_objects(self, bucket_name, prefix=None, match_pattern = None):
        '''
        Return a list of objects for the given bucket and prefix.
        :param bucket_name: Name of the bucket.
        :param prefix: Prefix to filter object names.
        :return: List of objects in bucket that match the given prefix.
        :rtype: list of str
        '''
        try:
            prefix = '' if prefix is None else prefix
            paginator = self.s3_client.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

            object_list = []
            for page in page_iterator:
                if 'Contents' in page:
                    for item in page['Contents']:
                        if match_pattern is None or (match_pattern is not None and match(match_pattern, item['Key'])):
                            object_list.append(item)
            return object_list
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == '404':
                raise StorageNoSuchKeyError(
                    bucket_name, '' if prefix is None else prefix)
            else:
                raise e

    def list_keys(self, bucket_name, prefix=None):
        '''
        Return a list of keys for the given prefix.
        :param bucket_name: Name of the bucket.
        :param prefix: Prefix to filter object names.
        :return: List of keys in bucket that match the given prefix.
        :rtype: list of str
        '''
        try:
            prefix = '' if prefix is None else prefix
            paginator = self.s3_client.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

            key_list = []
            for page in page_iterator:
                if 'Contents' in page:
                    for item in page['Contents']:
                        key_list.append(item['Key'])
            return key_list
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == '404':
                raise StorageNoSuchKeyError(bucket_name, prefix)
            else:
                raise e
