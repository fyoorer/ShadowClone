#
# (C) Copyright IBM Corp. 2020
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
import uuid
import sys
import json
import flask
import logging
from lithops.version import __version__
from lithops.utils import setup_lithops_logger, b64str_to_dict,\
    iterchunks
from lithops.worker import function_handler
from lithops.worker import function_invoker
from lithops.worker.utils import get_runtime_metadata
from lithops.constants import JOBS_PREFIX
from lithops.storage.storage import InternalStorage


proxy = flask.Flask(__name__)

logger = logging.getLogger('lithops.worker')


@proxy.route('/', methods=['POST'])
def run():
    def error():
        response = flask.jsonify({'error': 'The action did not receive a dictionary as an argument.'})
        response.status_code = 404
        return complete(response)

    message = flask.request.get_json(force=True, silent=True)
    if message and not isinstance(message, dict):
        return error()

    setup_lithops_logger(message['log_level'])

    act_id = str(uuid.uuid4()).replace('-', '')[:12]
    os.environ['__LITHOPS_ACTIVATION_ID'] = act_id
    os.environ['__LITHOPS_BACKEND'] = 'Code Engine (Knative)'

    if 'remote_invoker' in message:
        logger.info(f"Lithops v{__version__} - Starting Code Engine (Knative) invoker")
        function_invoker(message)
    else:
        logger.info(f"Lithops v{__version__} - Starting Code Engine (Knative) execution")
        function_handler(message)

    response = flask.jsonify({"activationId": act_id})
    response.status_code = 202

    return complete(response)


@proxy.route('/metadata', methods=['GET', 'POST'])
def metadata_task():
    setup_lithops_logger(logging.INFO)
    logger.info(f"Lithops v{__version__} - Generating metadata")
    runtime_meta = get_runtime_metadata()
    response = flask.jsonify(runtime_meta)
    response.status_code = 200
    logger.info("Done!")

    return complete(response)


def complete(response):
    # Add sentinel to stdout/stderr
    sys.stdout.write('%s\n' % 'XXX_THE_END_OF_AN_ACTIVATION_XXX')
    sys.stdout.flush()

    return response


def run_knative_server():
    port = int(os.getenv('PORT', 8080))
    proxy.run(debug=True, host='0.0.0.0', port=port)


def extract_runtime_metadata(payload):
    logger.info(f"Lithops v{__version__} - Generating metadata")
    runtime_meta = get_runtime_metadata()

    internal_storage = InternalStorage(payload)
    status_key = '/'.join([JOBS_PREFIX, payload['runtime_name']+'.meta'])
    logger.info(f"Runtime metadata key {status_key}")
    dmpd_response_status = json.dumps(runtime_meta)
    internal_storage.put_data(status_key, dmpd_response_status)


def run_ce_job(action, encoded_payload):
    logger.info(f"Lithops v{__version__} - Starting Code Engine (Job) execution")

    payload = b64str_to_dict(encoded_payload)

    setup_lithops_logger(payload['log_level'])

    if (action == 'metadata'):
        extract_runtime_metadata(payload)
        return {"Execution": "Finished"}

    job_index = int(os.environ['JOB_INDEX'])
    payload['JOB_INDEX'] = job_index
    logger.info(f"Action {action}. Job Index {job_index}")

    act_id = str(uuid.uuid4()).replace('-', '')[:12]
    os.environ['__LITHOPS_ACTIVATION_ID'] = act_id
    os.environ['__LITHOPS_BACKEND'] = 'Code Engine (Job)'

    chunksize = payload['chunksize']
    call_ids_ranges = [call_ids_range for call_ids_range in iterchunks(payload['call_ids'], chunksize)]
    call_ids = call_ids_ranges[job_index]
    data_byte_ranges = [payload['data_byte_ranges'][int(call_id)] for call_id in call_ids]

    payload['call_ids'] = call_ids
    payload['data_byte_ranges'] = data_byte_ranges

    function_handler(payload)

    return {"Execution": "Finished"}


if __name__ == '__main__':
    if 'JOB_INDEX' in os.environ:
        run_ce_job(sys.argv[1:][0], sys.argv[1:][1])
    else:
        run_knative_server()
