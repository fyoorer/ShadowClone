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
import uuid
import json
import logging
import flask
import time
import requests
from functools import partial

from lithops.version import __version__
from lithops.utils import setup_lithops_logger, b64str_to_dict,\
    iterchunks
from lithops.worker import function_handler
from lithops.worker.utils import get_runtime_metadata
from lithops.constants import JOBS_PREFIX
from lithops.storage.storage import InternalStorage


logger = logging.getLogger('lithops.worker')

proxy = flask.Flask(__name__)

MASTER_PORT = 8080

JOB_INDEXES = {}


@proxy.route('/getid/<jobkey>/<total_calls>', methods=['GET'])
def get_id(jobkey, total_calls):
    global JOB_INDEXES

    if jobkey not in JOB_INDEXES:
        JOB_INDEXES[jobkey] = 0
    else:
        JOB_INDEXES[jobkey] += 1

    call_id = '-1' if JOB_INDEXES[jobkey] >= int(total_calls) else str(JOB_INDEXES[jobkey])
    remote_host = flask.request.remote_addr
    proxy.logger.info('Sending ID {} to Host {}'.format(call_id, remote_host))

    return call_id


def run_master_server():
    proxy.logger.setLevel(logging.DEBUG)
    proxy.run(debug=True, host='0.0.0.0', port=MASTER_PORT)


def extract_runtime_meta(encoded_payload):
    logger.info(f"Lithops v{__version__} - Generating metadata")

    payload = b64str_to_dict(encoded_payload)

    setup_lithops_logger(payload['log_level'])

    runtime_meta = get_runtime_metadata()

    internal_storage = InternalStorage(payload)
    status_key = '/'.join([JOBS_PREFIX, payload['runtime_name']+'.meta'])
    logger.info(f"Runtime metadata key {status_key}")
    dmpd_response_status = json.dumps(runtime_meta)
    internal_storage.put_data(status_key, dmpd_response_status)


def run_job(encoded_payload):
    logger.info(f"Lithops v{__version__} - Starting kubernetes execution")

    payload = b64str_to_dict(encoded_payload)
    setup_lithops_logger(payload['log_level'])

    total_calls = payload['total_calls']
    job_key = payload['job_key']
    master_ip = os.environ['MASTER_POD_IP']

    chunksize = payload['chunksize']
    call_ids_ranges = [call_ids_range for call_ids_range in iterchunks(payload['call_ids'], chunksize)]
    data_byte_ranges = payload['data_byte_ranges']

    job_finished = False
    while not job_finished:
        job_index = None

        while job_index is None:
            try:
                url = f'http://{master_ip}:{MASTER_PORT}/getid/{job_key}/{total_calls}'
                res = requests.get(url)
                job_index = int(res.text)
            except Exception:
                time.sleep(0.1)

        if job_index == -1:
            job_finished = True
            continue

        act_id = str(uuid.uuid4()).replace('-', '')[:12]
        os.environ['__LITHOPS_ACTIVATION_ID'] = act_id
        os.environ['__LITHOPS_BACKEND'] = 'k8s'

        logger.info("Activation ID: {} - Job Index: {}".format(act_id, job_index))

        call_ids = call_ids_ranges[job_index]
        dbr = [data_byte_ranges[int(call_id)] for call_id in call_ids]
        payload['call_ids'] = call_ids
        payload['data_byte_ranges'] = dbr

        function_handler(payload)


if __name__ == '__main__':
    action = sys.argv[1]
    encoded_payload = sys.argv[2]

    switcher = {
        'get_metadata': partial(extract_runtime_meta, encoded_payload),
        'run_job': partial(run_job, encoded_payload),
        'run_master': run_master_server
    }

    func = switcher.get(action, lambda: "Invalid command")
    func()
