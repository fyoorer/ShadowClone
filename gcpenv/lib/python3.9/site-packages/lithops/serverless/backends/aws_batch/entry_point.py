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
import logging
import json
import uuid

from lithops.storage import InternalStorage
from lithops.version import __version__
from lithops.utils import setup_lithops_logger, iterchunks
from lithops.worker import function_handler
from lithops.worker.utils import get_runtime_metadata

logger = logging.getLogger('lithops.worker')

if __name__ == '__main__':
    print(os.environ)
    action = os.getenv('__LITHOPS_ACTION')
    os.environ['__LITHOPS_BACKEND'] = 'AWS Batch'

    if action == 'get_metadata':
        lithops_conf_json = os.environ['__LITHOPS_PAYLOAD']
        lithops_conf = json.loads(lithops_conf_json)
        setup_lithops_logger(lithops_conf.get('log_level', logging.INFO))
        logger.info("Lithops v{} - Generating metadata".format(__version__))
        runtime_meta = get_runtime_metadata()
        internal_storage = InternalStorage(lithops_conf)
        status_key = lithops_conf['runtime_name'] + '.meta'
        logger.info("Runtime metadata key {}".format(status_key))
        runtime_meta_json = json.dumps(runtime_meta)
        internal_storage.put_data(status_key, runtime_meta_json)

    elif action == 'run_job':
        lithops_payload_json = os.environ['__LITHOPS_PAYLOAD']
        lithops_payload = json.loads(lithops_payload_json)
        setup_lithops_logger(lithops_payload.get('log_level', logging.INFO))

        logger.info("Lithops v{} - Starting AWS Batch execution".format(__version__))

        job_index = int(os.environ.get('AWS_BATCH_JOB_ARRAY_INDEX', 0))
        lithops_payload['JOB_INDEX'] = job_index
        logger.info('Job index {}'.format(job_index))

        act_id = str(uuid.uuid4()).replace('-', '')[:12]
        os.environ['__LITHOPS_ACTIVATION_ID'] = act_id

        chunksize = lithops_payload['chunksize']
        call_ids_ranges = [call_ids_range for call_ids_range in iterchunks(lithops_payload['call_ids'], chunksize)]
        call_ids = call_ids_ranges[job_index]
        data_byte_ranges = [lithops_payload['data_byte_ranges'][int(call_id)] for call_id in call_ids]

        lithops_payload['call_ids'] = call_ids
        lithops_payload['data_byte_ranges'] = data_byte_ranges

        function_handler(lithops_payload)
    else:
        raise Exception('Unknown action {}'.format(action))
