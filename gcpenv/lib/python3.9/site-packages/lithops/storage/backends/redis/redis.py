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
import io
import redis
import shutil
import logging
from lithops.storage.utils import StorageNoSuchKeyError
from lithops.constants import STORAGE_CLI_MSG


logger = logging.getLogger(__name__)


class RedisBackend:
    def __init__(self, config):
        logger.debug("Creating Redis storage client")
        self.user_agent = config.pop('user_agent')
        self.config = config
        self.host = self.config['host']
        self._client = redis.Redis(**config)

        msg = STORAGE_CLI_MSG.format('Redis')
        logger.info("{} - Host: {}".format(msg, self.host))

    def get_client(self):
        return self._client

    def put_object(self, bucket_name, key, data):
        """
        Put an object in Redis. Override the object if the key already exists.
        :param bucket_name: bucket name
        :param key: key of the object.
        :param data: data of the object
        :type data: str/bytes
        :return: None
        """
        if not isinstance(data, (str, bytes, bytearray)):
            raise TypeError(type(data), 'valid types: {}'.format((str, bytes, bytearray)))

        redis_key = self._format_key(bucket_name, key)
        components = redis_key.split('/')

        # NOTE: could use a lua script and add from the lowest
        # to the highest dir and stop when SADD returns 0 since
        # then we can assume higher dirs already exist
        pipeline = self._client.pipeline(False)

        # create parent dirs
        for i in range(1, len(components) - 1):
            loc = '/'.join(components[:i]) + '/'
            pipeline.sadd(loc, components[i] + '/')

        # add file to lowest dir
        loc = '/'.join(components[:-1]) + '/'
        pipeline.sadd(loc, components[-1])

        # set actual key
        pipeline.set(redis_key, data)
        pipeline.execute()

    def get_object(self, bucket_name, key, stream=False, extra_get_args={}):
        """
        Get object from Redis with a key.
        Throws StorageNoSuchKeyError if the given key does not exist.
        :param bucket_name: bucket name
        :param key: key of the object
        :return: Data of the object
        :rtype: str/bytes
        """

        redis_key = self._format_key(bucket_name, key)
        try:
            if 'Range' in extra_get_args:  # expected format: Range='bytes=L-H'
                bytes_range = extra_get_args.pop('Range')[6:]
                start, end = self._parse_range(bytes_range)
                data = self._client.getrange(redis_key, start, end)
            else:
                data = self._client.get(redis_key)

        except redis.exceptions.ResponseError:
            raise StorageNoSuchKeyError(bucket_name, key)

        if data is None:
            raise StorageNoSuchKeyError(bucket_name, key)

        if stream:
            return io.BytesIO(data)
        else:
            return data

    def upload_file(self, file_name, bucket, key=None, extra_args={}):
        """Upload a file

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
            with open(file_name, 'rb') as in_file:
                self.put_object(bucket, key, in_file)
        except Exception as e:
            logging.error(e)
            return False
        return True

    def download_file(self, bucket, key, file_name=None, extra_args={}):
        """Download a file

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
        Head object from Redis with a key.
        Throws StorageNoSuchKeyError if the given key does not exist.
        :param bucket_name: bucket name
        :param key: key of the object
        :return: Data of the object
        :rtype: dict
        """
        redis_key = self._format_key(bucket_name, key)
        try:
            meta = self._client.debug_object(redis_key)
        except redis.exceptions.ResponseError:
            raise StorageNoSuchKeyError(bucket_name, key)

        meta['content-length'] = meta['serializedlength'] - 1
        return meta

    def delete_object(self, bucket_name, key):
        """
        Delete an object from storage.
        :param bucket_name: bucket name
        :param key: data key
        """
        self.delete_objects(bucket_name, [key])

    def delete_objects(self, bucket_name, key_list):
        """
        Delete a list of objects from storage.
        :param bucket_name: bucket name
        :param key_list: list of keys
        """
        redis_key_list = [self._format_key(bucket_name, k) for k in key_list]

        pipeline = self._client.pipeline(False)
        pipeline.delete(*redis_key_list)

        for full_path in redis_key_list:
            components = full_path.split('/')
            pdir = '/'.join(components[:-1]) + '/'
            pipeline.srem(pdir, components[-1])

        pipeline.execute()

    def head_bucket(self, bucket_name):
        """
        Head bucket from Redis with a name.
        Throws StorageNoSuchKeyError if the given bucket does not exist.
        :param bucket_name: name of the bucket
        :return: metadata of the bucket
        :rtype: dict
        """
        return bool(self._client.exists(self._format_key(bucket_name, '')))

    def list_objects(self, bucket_name, prefix=None, match_pattern = None):
        """
        Return a list of objects for the given bucket and prefix.
        :param bucket_name: name of the bucket.
        :param prefix: Prefix to filter object names.
        :return: List of objects in bucket that match the given prefix.
        :rtype: list of dict
        """
        pipeline = self._client.pipeline(False)
        for key in self.list_keys(bucket_name, prefix):
            pipeline.get(self._format_key(bucket_name, key))
        return pipeline.execute()

    def list_keys(self, bucket_name, prefix=None):
        """
        Return a list of keys for the given prefix.
        :param bucket_name: name of the bucket.
        :param prefix: Prefix to filter object names.
        :return: List of keys in bucket that match the given prefix.
        :rtype: list of str
        """
        prefix = prefix or ''
        redis_prefix = self._format_key(bucket_name, prefix)

        pdir = '/'.join(redis_prefix.split('/')[:-1]) + '/'
        dir_keys = [key.decode() for key in self._client.smembers(pdir)]
        key_list = []

        for key in dir_keys:
            full_key = pdir + key
            if full_key.startswith(redis_prefix):
                if full_key.endswith('/'):
                    key_list.extend(self._walk(bucket_name, full_key))
                else:
                    key_list.append(full_key)

        offset = len(bucket_name) + 1
        return [key[offset:] for key in key_list]

    def _walk(self, bucket_name, dir_key):
        dir_keys = [key.decode() for key in self._client.smembers(dir_key)]
        key_list = []

        for key in dir_keys:
            full_key = dir_key + key
            if full_key.endswith('/'):
                key_list.extend(self._walk(bucket_name, full_key))
            else:
                key_list.append(full_key)

        return key_list

    def _format_key(self, bucket, key):
        return '/'.join([bucket, key])

    def _parse_range(self, bytes_range):
        if '--' in bytes_range:
            bytes_range = bytes_range.replace('--', '-')
            sign = -1
        else:
            sign = 1

        if '-' in bytes_range:
            bytes_range = bytes_range.split('-')
            if bytes_range[0] == '':
                end = int(bytes_range[1]) * -1
                start = end
            else:
                start = int(bytes_range[0])
                end = int(bytes_range[1]) * sign
        else:
            start = end = int(bytes_range)

        return start, end
