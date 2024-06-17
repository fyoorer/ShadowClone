#
# (C) Copyright IBM Corp. 2022
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
import json
import time
import logging
from azure.storage.queue import QueueClient
from lithops.storage.storage import InternalStorage
from lithops.version import __version__
from lithops.utils import b64str_to_dict, setup_lithops_logger
from lithops.worker import function_handler
from lithops.worker.utils import get_runtime_metadata

logger = logging.getLogger('lithops.worker')

connection_string = os.environ['QueueConnectionString']
queue_name = os.environ['QueueName']
queue = QueueClient.from_connection_string(conn_str=connection_string, queue_name=queue_name)

def get_message():
    message = None
    while not message:
        try:
            message = next(queue.receive_messages())
            queue.delete_message(message)
        except Exception:
            time.sleep(5)

    return message


def extract_runtime_metadata(payload):
    runtime_meta = get_runtime_metadata()
    internal_storage = InternalStorage(payload['storage_config'])
    status_key = payload['containerapp_name']+'.meta'
    logger.info(f"Runtime metadata key {status_key}")
    dmpd_response_status = json.dumps(runtime_meta)
    internal_storage.put_data(status_key, dmpd_response_status)


def run_job(message):
    payload = b64str_to_dict(message.content)

    setup_lithops_logger(payload['log_level'])

    os.environ['__LITHOPS_ACTIVATION_ID'] = str(message.id)
    os.environ['__LITHOPS_BACKEND'] = 'Azure Container Apps'

    if 'get_metadata' in payload:
        logger.info(f"Lithops v{__version__} - Generating metadata")
        extract_runtime_metadata(payload)
    else:
        logger.info(f"Lithops v{__version__} - Starting Azure Container Apps execution")
        function_handler(payload)


if __name__ == '__main__':
    while True:
        message = get_message()
        run_job(message)
