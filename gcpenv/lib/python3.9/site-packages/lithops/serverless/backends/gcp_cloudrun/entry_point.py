#
# (C) Copyright IBM Corp. 2019
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

import sys
import os
import uuid
import flask
import logging
from lithops.version import __version__
from lithops.utils import setup_lithops_logger
from lithops.worker import function_handler
from lithops.worker import function_invoker
from lithops.worker.utils import get_runtime_metadata

logger = logging.getLogger('lithops.worker')


proxy = flask.Flask(__name__)


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

    act_id = uuid.uuid4().hex
    os.environ['__LITHOPS_ACTIVATION_ID'] = act_id
    os.environ['__LITHOPS_BACKEND'] = 'Google Cloud Run'

    if 'remote_invoker' in message:
        logger.info(f"Lithops v{__version__} - Starting GCP Cloud Run invoker")
        function_invoker(message)
    else:
        logger.info(f"Lithops v{__version__} - Starting GCP Cloud Run execution")
        function_handler(message)

    response = flask.jsonify({"activationId": act_id})
    response.status_code = 202

    return complete(response)


@proxy.route('/metadata', methods=['GET', 'POST'])
def preinstalls_task():
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


def main():
    port = int(os.getenv('PORT', 8080))
    proxy.run(debug=True, host='0.0.0.0', port=port)


if __name__ == '__main__':
    main()
