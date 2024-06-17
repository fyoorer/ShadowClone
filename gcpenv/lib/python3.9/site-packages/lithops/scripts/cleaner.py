#
# Copyright Cloudlab URV 2021
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
import sys
import time
import pickle
import logging
from concurrent.futures import ThreadPoolExecutor

from lithops.storage import Storage
from lithops.storage.utils import clean_bucket
from lithops.constants import JOBS_PREFIX, TEMP_PREFIX, CLEANER_DIR,\
    CLEANER_PID_FILE, CLEANER_LOG_FILE

log_file_stream = open(CLEANER_LOG_FILE, 'a')
sys.stdout = log_file_stream
sys.stderr = log_file_stream


logger = logging.getLogger('lithops')
logging.basicConfig(stream=log_file_stream, level=logging.INFO,
                    format=('%(asctime)s [%(levelname)s] %(module)s'
                            ' [%(threadName)s] - %(funcName)s: %(message)s'))
logger.setLevel('DEBUG')


def clean_executor_jobs(executor_id, executor_data):

    storage = None
    prefix = '/'.join([JOBS_PREFIX, executor_id])

    for file_data in executor_data:
        file_location = file_data['file_location']
        data = file_data['data']

        storage_config = data['storage_config']
        clean_cloudobjects = data['clean_cloudobjects']
        if not storage:
            storage = Storage(storage_config=storage_config)

        logger.info(f'Cleaning jobs {", ".join([job_key for job_key in data["jobs_to_clean"]])}')

        objects = storage.list_keys(storage.bucket, prefix)

        objects_to_delete = [
            key for key in objects
            if '-'.join(key.split('/')[1].split('-')[0:3])
            in data['jobs_to_clean']
        ]

        while objects_to_delete:
            storage.delete_objects(storage.bucket, objects_to_delete)
            time.sleep(5)
            objects = storage.list_keys(storage.bucket, prefix)
            objects_to_delete = [
                key for key in objects
                if '-'.join(key.split('/')[1].split('-')[0:3])
                in data['jobs_to_clean']
            ]

        if clean_cloudobjects:
            for job_key in data['jobs_to_clean']:
                prefix = '/'.join([TEMP_PREFIX, job_key])
                clean_bucket(storage, storage.bucket, prefix)

        if os.path.exists(file_location):
            os.remove(file_location)
        logger.info('Finished')


def clean_cloudobjects(cloudobjects_data):
    file_location = cloudobjects_data['file_location']
    data = cloudobjects_data['data']

    logger.info('Going to clean cloudobjects')
    cos_to_clean = data['cos_to_clean']
    storage_config = data['storage_config']
    storage = Storage(storage_config=storage_config)

    for co in cos_to_clean:
        if co.backend == storage.backend:
            logging.info('Cleaning {}://{}/{}'.format(co.backend,
                                                      co.bucket,
                                                      co.key))
            storage.delete_object(co.bucket, co.key)

    if os.path.exists(file_location):
        os.remove(file_location)
    logger.info('Finished')


def clean_functions(functions_data):
    file_location = functions_data['file_location']
    data = functions_data['data']

    executor_id = data['fn_to_clean']
    logger.info(f'Going to clean functions from {executor_id}')
    storage_config = data['storage_config']
    storage = Storage(storage_config=storage_config)
    prefix = '/'.join([JOBS_PREFIX, executor_id]) + '/'
    key_list = storage.list_keys(storage.bucket, prefix)
    storage.delete_objects(storage.bucket, key_list)

    if os.path.exists(file_location):
        os.remove(file_location)
    logger.info('Finished')


def clean():

    while True:
        executor_jobs = {}
        cloudobjects = []
        functions = []

        files_to_clean = os.listdir(CLEANER_DIR)

        if len(files_to_clean) <= 2:
            break

        for file_name in files_to_clean:
            file_location = os.path.join(CLEANER_DIR, file_name)
            if file_location in [CLEANER_LOG_FILE, CLEANER_PID_FILE]:
                continue

            with open(file_location, 'rb') as pk:
                data = pickle.load(pk)

            if 'jobs_to_clean' in data:
                # group data by executor_id
                executor_id, job_id = next(iter(data['jobs_to_clean'])).rsplit('-', 1)
                if executor_id not in executor_jobs:
                    executor_jobs[executor_id] = []
                executor_jobs[executor_id].append({'file_location': file_location, 'data': data})

            elif 'cos_to_clean' in data:
                cloudobjects.append({'file_location': file_location, 'data': data})

            elif 'fn_to_clean' in data:
                functions.append({'file_location': file_location, 'data': data})

        if executor_jobs:
            with ThreadPoolExecutor(max_workers=32) as ex:
                for executor_id in executor_jobs:
                    ex.submit(clean_executor_jobs, executor_id, executor_jobs[executor_id])

        if cloudobjects:
            with ThreadPoolExecutor(max_workers=32) as ex:
                for cloudobjects_data in cloudobjects:
                    ex.submit(clean_cloudobjects, cloudobjects_data)

        if functions:
            with ThreadPoolExecutor(max_workers=32) as ex:
                for function_data in functions:
                    ex.submit(clean_functions, function_data)

        time.sleep(5)


if __name__ == '__main__':
    if not os.path.isfile(CLEANER_PID_FILE):
        logger.info("Starting Job and Cloudobject Cleaner")
        with open(CLEANER_PID_FILE, 'w') as cf:
            cf.write(str(os.getpid()))
        try:
            clean()
        except Exception as e:
            raise e
        finally:
            os.remove(CLEANER_PID_FILE)
        logger.info("Job and Cloudobject Cleaner finished")
