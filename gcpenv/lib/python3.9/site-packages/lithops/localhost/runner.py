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
import sys
import json
import platform
import logging
import uuid
import multiprocessing as mp
from pathlib import Path

from lithops.worker import function_handler
from lithops.worker.utils import get_runtime_metadata
from lithops.constants import LITHOPS_TEMP_DIR, JOBS_DIR, LOGS_DIR,\
    RN_LOG_FILE, LOGGER_FORMAT

log_file_stream = open(RN_LOG_FILE, 'a')

os.makedirs(LITHOPS_TEMP_DIR, exist_ok=True)
os.makedirs(JOBS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

logging.basicConfig(stream=log_file_stream,
                    level=logging.INFO,
                    format=LOGGER_FORMAT)
logger = logging.getLogger('lithops.localhost.runner')


# Change spawn method for MacOS
if platform.system() == 'Darwin':
    mp.set_start_method("fork")


def run_job():
    sys.stdout = log_file_stream
    sys.stderr = log_file_stream

    job_filename = sys.argv[2]
    logger.info(f'Got {job_filename} job file')

    with open(job_filename, 'rb') as jf:
        job_payload = json.load(jf)

    executor_id = job_payload['executor_id']
    job_id = job_payload['job_id']
    job_key = job_payload['job_key']

    logger.info(f'ExecutorID {executor_id} | JobID {job_id} - Starting execution')

    act_id = str(uuid.uuid4()).replace('-', '')[:12]
    os.environ['__LITHOPS_ACTIVATION_ID'] = act_id
    os.environ['__LITHOPS_BACKEND'] = 'Localhost'

    try:
        function_handler(job_payload)
    except KeyboardInterrupt:
        pass

    done = os.path.join(JOBS_DIR, job_key + '.done')
    Path(done).touch()

    if os.path.exists(job_filename):
        os.remove(job_filename)

    logger.info(f'ExecutorID {executor_id} | JobID {job_id} - Execution Finished')


def extract_runtime_meta():
    runtime_meta = get_runtime_metadata()
    print(json.dumps(runtime_meta))


if __name__ == "__main__":
    logger.info('Starting Localhost job runner')
    command = sys.argv[1]
    logger.info(f'Received command: {command}')

    switcher = {
        'get_metadata': extract_runtime_meta,
        'run_job': run_job
    }

    switcher.get(command, lambda: "Invalid command")()
    log_file_stream.close()
