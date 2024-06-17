#
# Copyright 2018 PyWren Team
# Copyright IBM Corp. 2020
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
import time
import logging
from lithops.constants import JOBS_PREFIX


logger = logging.getLogger(__name__)


func_key_suffix = "func.pickle"
agg_data_key_suffix = "aggdata.pickle"
data_key_suffix = "data.pickle"
output_key_suffix = "output.pickle"
status_key_suffix = "status.json"
init_key_suffix = ".init"


class StorageNoSuchKeyError(Exception):
    def __init__(self, bucket, key):
        msg = f"No such key /{bucket}/{key} found in storage."
        super(StorageNoSuchKeyError, self).__init__(msg)


class StorageConfigMismatchError(Exception):
    def __init__(self, current_path, prev_path):
        msg = f"The data is stored at {prev_path}, but current storage is configured at {current_path}"
        super(StorageConfigMismatchError, self).__init__(msg)


class CloudObject:
    def __init__(self, backend, bucket, key):
        self.backend = backend
        self.bucket = bucket
        self.key = key

    def __str__(self):
        path = f'{self.backend}://{self.bucket}/{self.key}'
        return f'<CloudObject at {path}>'


class CloudObjectUrl:
    def __init__(self, url):
        self.url = url

    def __str__(self):
        return f'<CloudObject at {self.url}>'


class CloudObjectLocal:
    def __init__(self, path):
        self.path = path
        self.bucket = os.path.dirname(path)
        self.key = os.path.basename(path)

    def __str__(self):
        return f'<CloudObject at {self.path}>'


def clean_bucket(storage, bucket, prefix, sleep=5):
    """
    Deletes all the files from COS. These files include the function,
    the data serialization and the function invocation results.
    """
    msg = f"Going to delete all objects from bucket '{bucket}'"
    msg = msg + f" and prefix '{prefix}'" if prefix else msg
    logger.info(msg)
    total_objects = 0
    objects_to_delete = storage.list_keys(bucket, prefix)

    while objects_to_delete:
        total_objects = total_objects + len(objects_to_delete)
        storage.delete_objects(bucket, objects_to_delete)
        time.sleep(sleep)
        objects_to_delete = storage.list_keys(bucket, prefix)

    logger.info(f'Finished deleting objects, total found: {total_objects}')


def create_job_key(executor_id, job_id):
    """
    Create job key
    :param executor_id: prefix
    :param job_id: Job's ID
    :return: exec id
    """
    return '-'.join([executor_id, job_id])


def create_func_key(executor_id, function_hash):
    """
    Create function key
    :param prefix: prefix
    :param executor_id: callset's ID
    :return: function key
    """
    return '/'.join([JOBS_PREFIX, executor_id, f'{function_hash}.{func_key_suffix}'])


def create_data_key(executor_id, job_id):
    """
    Create aggregate data key
    :param prefix: prefix
    :param executor_id: callset's ID
    :param job_id: Job's ID
    :return: a key for aggregate data
    """
    job_key = create_job_key(executor_id, job_id)
    return '/'.join([JOBS_PREFIX, job_key, agg_data_key_suffix])


def create_output_key(executor_id, job_id, call_id):
    """
    Create output key
    :param prefix: prefix
    :param executor_id: Executor's ID
    :param job_id: Job's ID
    :param call_id: call's ID
    :return: output key
    """
    job_key = create_job_key(executor_id, job_id)
    return '/'.join([JOBS_PREFIX, job_key, call_id, output_key_suffix])


def create_status_key(executor_id, job_id, call_id):
    """
    Create status key
    :param prefix: prefix
    :param executor_id: Executor's ID
    :param job_id: Job's ID
    :param call_id: call's ID
    :return: status key
    """
    job_key = create_job_key(executor_id, job_id)
    return '/'.join([JOBS_PREFIX, job_key, call_id, status_key_suffix])


def create_init_key(executor_id, job_id, call_id, act_id):
    """
    Create init key
    :param prefix: prefix
    :param executor_id: Executor's ID
     :param job_id: Job's ID
    :param call_id: call's ID
    :return: output key
    """
    job_key = create_job_key(executor_id, job_id)
    return '/'.join([JOBS_PREFIX, job_key, call_id, f'{act_id}{init_key_suffix}'])


def get_storage_path(storage_config):
    storage_bucket = storage_config['bucket']
    storage_backend = storage_config['backend']

    return [storage_backend, storage_bucket]


def check_storage_path(config, prev_path):
    current_path = get_storage_path(config)
    if current_path != prev_path:
        raise StorageConfigMismatchError(current_path, prev_path)
