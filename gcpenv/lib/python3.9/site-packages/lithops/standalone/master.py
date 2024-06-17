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
import copy
import time
import json
import uuid
import flask
import queue
import logging
import requests
from pathlib import Path
import concurrent.futures as cf
from gevent.pywsgi import WSGIServer
from threading import Thread
from concurrent.futures import ThreadPoolExecutor

from lithops.constants import LITHOPS_TEMP_DIR, SA_LOG_FILE, JOBS_DIR,\
    SA_SERVICE_PORT, SA_CONFIG_FILE, SA_DATA_FILE
from lithops.localhost.localhost import LocalhostHandler
from lithops.standalone.standalone import LithopsValidationError
from lithops.utils import verify_runtime_name, iterchunks, setup_lithops_logger
from lithops.standalone.utils import get_worker_setup_script
from lithops.standalone.keeper import BudgetKeeper
from lithops.version import __version__ as lithops_version


log_format = "%(asctime)s\t[%(levelname)s] %(name)s:%(lineno)s -- %(message)s"
setup_lithops_logger(logging.DEBUG, filename=SA_LOG_FILE, log_format=log_format)
logger = logging.getLogger('lithops.standalone.master')

app = flask.Flask(__name__)

MAX_INSTANCE_CREATE_RETRIES = 2
REUSE_WORK_QUEUE_NAME = 'all'

exec_mode = 'consume'
workers = {}
workers_state = {}

standalone_config = None
standalone_handler = None
budget_keeper = None
work_queues = {}
master_ip = None

# variables for consume mode
localhost_manager_process = None
localhos_handler = None
last_job_key = None


def is_worker_free(worker):
    """
    Checks if the Lithops service is ready and free in the worker VM instance
    """
    url = f"http://{worker.private_ip}:{SA_SERVICE_PORT}/ping"
    r = requests.get(url, timeout=0.5)
    if r.status_code == 200:
        if r.json()['status'] == 'free':
            return True
    return False


def setup_worker(worker_info, work_queue_name):
    """
    Run worker process
    Install all the Lithops dependencies into the worker.
    Runs the job
    """
    global workers, workers_state

    worker = standalone_handler.backend.get_instance(**worker_info, public=False)
    logger.debug(f'Starting setup for {worker}')

    max_instance_create_retries = standalone_config.get('worker_create_retries', MAX_INSTANCE_CREATE_RETRIES)

    def wait_worker_ready(worker):
        instance_ready_retries = 1

        while instance_ready_retries <= max_instance_create_retries:
            try:
                workers_state[worker.name] = {'state': 'starting'}
                worker.wait_ready()
                break
            except TimeoutError as e:  # VM not started in time
                workers_state[worker.name] = {'state': 'error', 'err': str(e)}
                if instance_ready_retries == max_instance_create_retries:
                    raise e
                logger.warning(f'Timeout Error. Recreating VM instance {worker.name}')
                worker.delete()
                worker.create()
                instance_ready_retries += 1

    wait_worker_ready(worker)

    instance_validate_retries = 1
    while instance_validate_retries <= max_instance_create_retries:
        try:
            logger.debug(f'Validating {worker.name}')
            worker.validate_capabilities()
            break
        except LithopsValidationError as e:
            logger.debug(f'{worker.name} validation error: {e}')
            workers_state[worker.name] = {'state': 'error', 'err': str(e)}
            if instance_validate_retries == max_instance_create_retries:
                workers_state[worker.name] = {'state': 'setup', 'err': str(e)}
                break
            logger.warning(f'Worker {worker.name} setup failed with error {e} after {instance_validate_retries} retries')
            worker.delete()
            worker.create()
            instance_validate_retries += 1
            wait_worker_ready(worker)

    # upload zip lithops package
    logger.debug(f'Uploading lithops files to {worker}')
    worker.get_ssh_client().upload_local_file(
        '/opt/lithops/lithops_standalone.zip',
        '/tmp/lithops_standalone.zip')

    logger.debug(f'Executing lithops installation process on {worker}')

    vm_data = {'name': worker.name,
               'private_ip': worker.private_ip,
               'instance_id': worker.instance_id,
               'ssh_credentials': worker.ssh_credentials,
               'master_ip': master_ip,
               'work_queue': work_queue_name}

    remote_script = "/tmp/install_lithops.sh"
    script = get_worker_setup_script(standalone_config, vm_data)
    worker.get_ssh_client().upload_data_to_file(script, remote_script)
    cmd = f"chmod 777 {remote_script}; sudo {remote_script};"
    worker.get_ssh_client().run_remote_command(cmd, run_async=True)
    worker.del_ssh_client()
    logger.debug(f'Installation script submitted to {worker}')
    workers_state[worker.name] = {'state': 'running', 'err': workers_state[worker.name].get('err')}

    logger.debug(f'Appending {worker.name} to Worker list')
    workers[worker.name] = worker


def start_workers(job_payload, work_queue_name):
    """
    Creates the workers (if any)
    """
    workers = job_payload['worker_instances']

    if not workers:
        return

    futures = []
    with ThreadPoolExecutor(len(workers)) as executor:
        for worker_info in workers:
            futures.append(executor.submit(setup_worker, worker_info, work_queue_name))

    for future in cf.as_completed(futures):
        try:
            future.result()
        except Exception as e:
            # TODO consider to update worker state
            logger.error(e)

    logger.debug(f'All workers set up for work queue "{work_queue_name}"')


def run_job_local(work_queue):
    """
    Localhost jobs manager process for consume mode
    """
    global localhos_handler
    global last_job_key

    pull_runtime = standalone_config.get('pull_runtime', False)

    def wait_job_completed(job_key):
        done = os.path.join(JOBS_DIR, job_key + '.done')
        while True:
            if os.path.isfile(done):
                break
            time.sleep(1)

    try:
        localhos_handler = LocalhostHandler({'pull_runtime': pull_runtime})

        while True:
            job_payload = work_queue.get()
            job_key = job_payload['job_key']
            last_job_key = job_key
            job_payload['config']['lithops']['backend'] = 'localhost'
            localhos_handler.invoke(job_payload)
            wait_job_completed(job_key)

    except Exception as e:
        logger.error(e)


def run_job_worker(job_payload, work_queue):
    """
    Process responsible to wait for workers to become ready, and
    submit individual tasks of the job to them
    """
    job_key = job_payload['job_key']
    call_ids = job_payload['call_ids']
    chunksize = job_payload['chunksize']

    for call_ids_range in iterchunks(call_ids, chunksize):
        task_payload = copy.deepcopy(job_payload)
        dbr = task_payload['data_byte_ranges']
        task_payload['call_ids'] = call_ids_range
        task_payload['data_byte_ranges'] = [dbr[int(call_id)] for call_id in call_ids_range]
        work_queue.put(task_payload)

    while not work_queue.empty():
        time.sleep(1)

    done = os.path.join(JOBS_DIR, job_key + '.done')
    Path(done).touch()

    logger.debug(f'Job process {job_key} finished')


def error(msg):
    response = flask.jsonify({'error': msg})
    response.status_code = 404
    return response


@app.route('/workers', methods=['GET'])
def get_workers():
    """
    Returns the number of free workers
    """
    global workers
    global budget_keeper

    # update last_usage_time to prevent race condition when keeper stops the vm
    budget_keeper.last_usage_time = time.time()

    current_workers = [(worker.name, worker.private_ip) for worker in workers.values()]
    logger.debug(f'Current workers: {current_workers}')

    free_workers = []

    def check_worker(worker):
        if is_worker_free(worker):
            free_workers.append((
                worker.name,
                worker.private_ip,
                worker.instance_id,
                worker.ssh_credentials)
            )

    if workers:
        with ThreadPoolExecutor(len(workers)) as ex:
            ex.map(check_worker, workers.values())

    logger.debug(f'Total free workers: {len(free_workers)}')

    response = flask.jsonify(free_workers)
    response.status_code = 200

    return response


@app.route('/workers-state', methods=['GET'])
def get_workers_state():
    """
    Returns the current workers state
    """
    logger.debug(f'Workers state: {workers_state}')
    return flask.jsonify(workers_state)


@app.route('/get-task/<work_queue_name>', methods=['GET'])
def get_task(work_queue_name):
    """
    Returns a task from the work queue
    """
    global work_queues

    try:
        task_payload = work_queues.setdefault(work_queue_name, queue.Queue()).get(False)
        response = flask.jsonify(task_payload)
        response.status_code = 200
        job_key = task_payload['job_key']
        calls = task_payload['call_ids']
        worker_ip = flask.request.remote_addr
        logger.debug(f'Worker {worker_ip} retrieved Job {job_key} - Calls {calls}')
    except queue.Empty:
        response = ('', 204)

    return response


def stop_job_process(job_key_list):
    """
    Stops a job process
    """
    global localhos_handler
    global work_queues

    for job_key in job_key_list:
        logger.debug(f'Received SIGTERM: Stopping job process {job_key}')

        if exec_mode == 'consume':
            if job_key == last_job_key:
                # kill current running job process
                localhos_handler.clear()
                done = os.path.join(JOBS_DIR, job_key + '.done')
                Path(done).touch()
            else:
                # Delete job_payload from pending queue
                work_queue = work_queues['local']
                tmp_queue = []
                while not work_queue.empty():
                    try:
                        job_payload = work_queue.get(False)
                        if job_payload['job_key'] != job_key:
                            tmp_queue.append(job_payload)
                    except Exception:
                        pass
                for job_payload in tmp_queue:
                    work_queue.put(job_payload)

        else:
            wqn = job_key if exec_mode == 'create' else REUSE_WORK_QUEUE_NAME
            # empty work queue
            work_queue = work_queues.setdefault(wqn, queue.Queue())
            while not work_queue.empty():
                try:
                    work_queue.get(False)
                except Exception:
                    pass

            def stop_task(worker):
                private_ip = worker['private_ip']
                url = f"http://{private_ip}:{SA_SERVICE_PORT}/stop/{job_key}"
                requests.post(url, timeout=0.5)

            # Send stop signal to all workers
            with ThreadPoolExecutor(len(workers)) as ex:
                ex.map(stop_task, workers.values())


@app.route('/stop', methods=['POST'])
def stop():
    """
    Stops received job processes
    """
    job_key_list = flask.request.get_json(force=True, silent=True)
    # Start a separate thread to do the task in background,
    # for not keeping the client waiting.
    Thread(target=stop_job_process, args=(job_key_list, )).start()

    return ('', 204)


@app.route('/run-job', methods=['POST'])
def run():
    """
    Run a job locally, in consume mode
    """
    global budget_keeper
    global work_queues
    global exec_mode
    global localhost_manager_process

    job_payload = flask.request.get_json(force=True, silent=True)
    if job_payload and not isinstance(job_payload, dict):
        return error('The action did not receive a dictionary as an argument.')

    try:
        runtime = job_payload['runtime_name']
        verify_runtime_name(runtime)
    except Exception as e:
        return error(str(e))

    job_key = job_payload['job_key']
    logger.debug('Received job {}'.format(job_key))

    budget_keeper.last_usage_time = time.time()
    budget_keeper.update_config(job_payload['config']['standalone'])
    budget_keeper.jobs[job_key] = 'running'

    exec_mode = job_payload['config']['standalone'].get('exec_mode', 'consume')

    if exec_mode == 'consume':
        # Consume mode runs jobs in this master VM
        work_queue_name = 'local'
        work_queue = work_queues.setdefault(work_queue_name, queue.Queue())
        if not localhost_manager_process:
            logger.debug('Starting manager process for localhost jobs')
            lmp = Thread(target=run_job_local, args=(work_queue, ), daemon=True)
            lmp.start()
            localhost_manager_process = lmp
        logger.debug(f'Putting job {job_key} into master queue')
        work_queue.put(job_payload)

    elif exec_mode in ['create', 'reuse']:
        # Create and reuse mode runs jobs on woker VMs
        logger.debug(f'Starting process for job {job_key}')
        work_queue_name = job_key if exec_mode == 'create' else REUSE_WORK_QUEUE_NAME
        work_queue = work_queues.setdefault(work_queue_name, queue.Queue())
        Thread(target=start_workers, args=(job_payload, work_queue_name)).start()
        Thread(target=run_job_worker, args=(job_payload, work_queue), daemon=True).start()

    act_id = str(uuid.uuid4()).replace('-', '')[:12]
    response = flask.jsonify({'activationId': act_id})
    response.status_code = 202

    return response


@app.route('/ping', methods=['GET'])
def ping():
    response = flask.jsonify({'response': lithops_version})
    response.status_code = 200
    return response


@app.route('/get-metadata', methods=['GET'])
def get_metadata():
    payload = flask.request.get_json(force=True, silent=True)
    if payload and not isinstance(payload, dict):
        return error('The action did not receive a dictionary as an argument.')

    try:
        runtime = payload['runtime']
        verify_runtime_name(runtime)
    except Exception as e:
        return error(str(e))

    pull_runtime = standalone_config.get('pull_runtime', False)
    lh = LocalhostHandler({'runtime': runtime, 'pull_runtime': pull_runtime})
    runtime_meta = lh.deploy_runtime(runtime)

    if 'lithops_version' in runtime_meta:
        logger.debug("Runtime metdata extracted correctly: Lithops "
                     f"{runtime_meta['lithops_version']}")
    response = flask.jsonify(runtime_meta)
    response.status_code = 200

    return response


def main():
    global standalone_config
    global standalone_handler
    global budget_keeper
    global master_ip

    os.makedirs(LITHOPS_TEMP_DIR, exist_ok=True)

    with open(SA_CONFIG_FILE, 'r') as cf:
        standalone_config = json.load(cf)

    # Delete ssh_key_filename
    backend = standalone_config['backend']
    if 'ssh_key_filename' in standalone_config[backend]:
        del standalone_config[backend]['ssh_key_filename']

    with open(SA_DATA_FILE, 'r') as ad:
        master_ip = json.load(ad)['private_ip']

    budget_keeper = BudgetKeeper(standalone_config)
    budget_keeper.start()

    standalone_handler = budget_keeper.sh

    server = WSGIServer(('0.0.0.0', SA_SERVICE_PORT), app, log=app.logger)
    server.serve_forever()


if __name__ == '__main__':
    main()
