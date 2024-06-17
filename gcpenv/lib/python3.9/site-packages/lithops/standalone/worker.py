#
# Copyright Cloudlab URV 2020
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
import time
import json
import flask
import requests
from pathlib import Path
from threading import Thread
from gevent.pywsgi import WSGIServer

from lithops.constants import LITHOPS_TEMP_DIR, SA_LOG_FILE, JOBS_DIR,\
    SA_SERVICE_PORT, SA_CONFIG_FILE, SA_DATA_FILE
from lithops.localhost.localhost import LocalhostHandler
from lithops.utils import verify_runtime_name, setup_lithops_logger
from lithops.standalone.keeper import BudgetKeeper

log_format = "%(asctime)s\t[%(levelname)s] %(name)s:%(lineno)s -- %(message)s"
setup_lithops_logger(logging.DEBUG, filename=SA_LOG_FILE, log_format=log_format)
logger = logging.getLogger('lithops.standalone.worker')

app = flask.Flask(__name__)

stanbdalone_config = None
budget_keeper = None
localhos_handler = None
last_job_key = None


@app.route('/ping', methods=['GET'])
def ping():
    bussy = localhos_handler.job_manager if localhos_handler else False
    response = flask.jsonify({'status': 'bussy' if bussy else 'free'})
    response.status_code = 200
    return response


@app.route('/stop/<job_key>', methods=['POST'])
def stop(job_key):
    if job_key == last_job_key:
        logger.debug(f'Received SIGTERM: Stopping job process {job_key}')
        localhos_handler.clear()
        done = os.path.join(JOBS_DIR, job_key + '.done')
        Path(done).touch()
    response = flask.jsonify({'response': 'cancel'})
    response.status_code = 200
    return response


def wait_job_completed(job_key):
    """
    Waits until the current job is completed
    """
    global budget_keeper

    done = os.path.join(JOBS_DIR, job_key + '.done')
    while True:
        if os.path.isfile(done):
            os.remove(done)
            budget_keeper.jobs[job_key] = 'done'
            break
        time.sleep(1)


def run_worker(master_ip, work_queue):
    """
    Run a job
    """
    global budget_keeper
    global localhos_handler
    global last_job_key

    pull_runtime = stanbdalone_config.get('pull_runtime', False)
    localhos_handler = LocalhostHandler({'pull_runtime': pull_runtime})

    while True:
        url = f'http://{master_ip}:{SA_SERVICE_PORT}/get-task/{work_queue}'
        logger.debug(f'Getting task from {url}')

        try:
            resp = requests.get(url)
        except Exception:
            time.sleep(1)
            continue

        if resp.status_code != 200:
            if stanbdalone_config.get('exec_mode') == 'reuse':
                time.sleep(1)
                continue
            else:
                logger.debug(f'All tasks completed from {url}')
                return

        job_payload = resp.json()

        try:
            runtime = job_payload['runtime_name']
            verify_runtime_name(runtime)
        except Exception:
            return

        job_key = job_payload['job_key']
        last_job_key = job_key

        budget_keeper.last_usage_time = time.time()
        budget_keeper.update_config(job_payload['config']['standalone'])
        budget_keeper.jobs[job_key] = 'running'

        try:
            localhos_handler.invoke(job_payload)
        except Exception as e:
            logger.error(e)

        wait_job_completed(job_key)


def main():
    global stanbdalone_config
    global budget_keeper

    os.makedirs(LITHOPS_TEMP_DIR, exist_ok=True)

    # read the Lithops standaole configuration file
    with open(SA_CONFIG_FILE, 'r') as cf:
        stanbdalone_config = json.load(cf)

    # Read the VM data file that contains the instance id, the master IP,
    # and the queue for getting tasks
    with open(SA_DATA_FILE, 'r') as ad:
        vm_data = json.load(ad)
        worker_ip = vm_data['private_ip']
        master_ip = vm_data['master_ip']
        work_queue = vm_data['work_queue']

    # Start the budget keeper. It is responsible to automatically terminate the
    # worker after X seconds
    budget_keeper = BudgetKeeper(stanbdalone_config)
    budget_keeper.start()

    # Start the http server. This will be used by the master VM to pìng this
    # worker and for canceling tasks
    def run_wsgi():
        server = WSGIServer((worker_ip, SA_SERVICE_PORT), app, log=app.logger)
        server.serve_forever()
    Thread(target=run_wsgi, daemon=True).start()

    # Start the worker that will get tasks from the work queue
    run_worker(master_ip, work_queue)

    # run_worker will run forever in reuse mode. In create mode it will
    # run until there are no more tasks in the queue.
    logger.debug('Finished')

    try:
        # Try to stop the current worker VM once no more pending tasks to run
        # in case of create mode
        budget_keeper.vm.stop()
    except Exception:
        pass


if __name__ == '__main__':
    main()
