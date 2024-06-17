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

import os
import oss2
import shutil
import logging

from lithops.storage.utils import StorageNoSuchKeyError
from lithops.utils import is_lithops_worker
from lithops.constants import STORAGE_CLI_MSG

from . import config

logger = logging.getLogger(__name__)


class AliyunObjectStorageServiceBackend:

    def __init__(self, oss_config):
        logger.debug("Creating Aliyun Object Storage Service client")
        self.oss_config = oss_config
        self.auth = oss2.Auth(self.oss_config['access_key_id'], self.oss_config['access_key_secret'])

        if is_lithops_worker():
            self.endpoint = self.oss_config['internal_endpoint']
        else:
            self.endpoint = self.oss_config['public_endpoint']

        self.region = self.endpoint.split('-', 1)[1].split('.')[0]

        # Connection pool size in aliyun_oss must be updated to avoid "connection pool is full" type errors.
        oss2.defaults.connection_pool_size = config.CONNECTION_POOL_SIZE

        msg = STORAGE_CLI_MSG.format('Aliyun Object Storage Service')
        logger.info(f"{msg} - Region: {self.region}")

    def _connect_bucket(self, bucket_name):
        if hasattr(self, 'bucket') and self.bucket.bucket_name == bucket_name:
            bucket = self.bucket
        else:
            self.bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
            bucket = self.bucket
        return bucket

    def get_client(self):
        return self

    def put_object(self, bucket_name, key, data):
        """
        Put an object in OSS. Override the object if the key already exists.
        Throws StorageNoSuchKeyError if the bucket does not exist.
        :param bucket_name: bucket name
        :param key: key of the object.
        :param data: data of the object
        :type data: str/bytes
        :return: None
        """
        if isinstance(data, str):
            data = data.encode()

        try:
            bucket = self._connect_bucket(bucket_name)
            bucket.put_object(key, data)
        except oss2.exceptions.NoSuchBucket:
            raise StorageNoSuchKeyError(bucket_name, '')

    def get_object(self, bucket_name, key, stream=False, extra_get_args={}):
        """
        Get object from OSS with a key. Throws StorageNoSuchKeyError if the given key does not exist.
        :param bucket_name: bucket name
        :param key: key of the object
        :return: Data of the object
        :rtype: str/bytes
        """
        try:
            bucket = self._connect_bucket(bucket_name)

            if 'Range' in extra_get_args:   # expected common format: Range='bytes=L-H'
                bytes_range = extra_get_args.pop('Range')
                if isinstance(bytes_range, str):
                    bytes_range = bytes_range[6:]
                    bytes_range = bytes_range.split('-')

                # Cannot use byte range surpassing the content length
                if int(bytes_range[0]) != 0:
                    object_length = bucket.head_object(key).content_length
                    if int(bytes_range[1]) >= object_length:
                        bytes_range[1] = object_length - 1

                extra_get_args['byte_range'] = (int(bytes_range[0]), int(bytes_range[1]))

            data = bucket.get_object(key=key, **extra_get_args)
            if stream:
                return data
            else:
                return data.read()

        except (oss2.exceptions.NoSuchKey, oss2.exceptions.NoSuchBucket):
            raise StorageNoSuchKeyError(bucket_name, key)

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
        """
        Head object from OSS with a key. Throws StorageNoSuchKeyError if the given key does not exist.
        :param bucket_name: bucket name
        :param key: key of the object
        :return: Data of the object
        :rtype: dict
        """
        bucket = self._connect_bucket(bucket_name)

        try:
            headobj = bucket.head_object(key)
            # adapted to match ibm_cos method
            metadata = vars(headobj)
            metadata['content-length'] = metadata.pop('content_length')
            return metadata
        except (oss2.exceptions.NoSuchKey, oss2.exceptions.NoSuchBucket):
            raise StorageNoSuchKeyError(bucket_name, key)

    def delete_object(self, bucket_name, key):
        """
        Delete an object from storage.
        :param bucket_name: bucket name
        :param key: data key
        """
        bucket = self._connect_bucket(bucket_name)
        bucket.delete_object(key)

    def delete_objects(self, bucket_name, key_list):
        """
        Delete a list of objects from storage.
        :param bucket_name: bucket name
        :param key_list: list of keys
        """
        bucket = self._connect_bucket(bucket_name)
        bucket.batch_delete_objects(key_list)

    def head_bucket(self, bucket_name):
        """
        Head bucket from OSS with a name. Throws StorageNoSuchKeyError if the given bucket does not exist.
        :param bucket_name: name of the bucket
        :return: metadata of the bucket
        :rtype: dict
        """
        bucket = self._connect_bucket(bucket_name)
        try:
            metadata = bucket.get_bucket_info()
            return vars(metadata)
        except oss2.exceptions.NoSuchBucket:
            raise StorageNoSuchKeyError(bucket_name, '')

    def list_objects(self, bucket_name, prefix=None, match_pattern = None):
        """
        Return a list of objects for the given bucket and prefix.
        :param bucket_name: name of the bucket.
        :param prefix: Prefix to filter object names.
        :return: List of objects in bucket that match the given prefix.
        :rtype: list of dict
        """
        bucket = self._connect_bucket(bucket_name)

        # adapted to match ibm_cos method
        prefix = '' if prefix is None else prefix
        try:
            res = bucket.list_objects(prefix=prefix, max_keys=1000)
            obj_list = [{'Key': obj.key, 'Size': obj.size} for obj in res.object_list]
            return obj_list

        except (oss2.exceptions.NoSuchKey, oss2.exceptions.NoSuchBucket):
            raise StorageNoSuchKeyError(bucket_name, prefix)

    def list_keys(self, bucket_name, prefix=None):
        """
        Return a list of keys for the given prefix.
        :param bucket_name: name of the bucket.
        :param prefix: Prefix to filter object names.
        :return: List of keys in bucket that match the given prefix.
        :rtype: list of str
        """
        bucket = self._connect_bucket(bucket_name)

        # adapted to match ibm_cos method
        prefix = '' if prefix is None else prefix
        try:
            res = bucket.list_objects(prefix=prefix, max_keys=1000)
            keys = [obj.key for obj in res.object_list]
            return [] if keys is None else keys

        except (oss2.exceptions.NoSuchKey, oss2.exceptions.NoSuchBucket):
            raise StorageNoSuchKeyError(bucket_name, prefix)
