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
import json
import threading
import time
import logging
import importlib
import requests
import shlex
import concurrent.futures as cf

from lithops.utils import is_lithops_worker, create_handler_zip
from lithops.constants import SA_SERVICE_PORT, SA_INSTALL_DIR, TEMP_DIR
from lithops.standalone.utils import ExecMode, get_master_setup_script
from lithops.version import __version__

logger = logging.getLogger(__name__)

class LithopsValidationError(Exception):
    pass


class StandaloneHandler:
    """
    A StandaloneHandler object is used by invokers and other components to access
    underlying standalone backend without exposing the implementation details.
    """

    def __init__(self, standalone_config):
        self.config = standalone_config
        self.backend_name = self.config['backend']
        self.start_timeout = self.config['start_timeout']
        self.exec_mode = self.config['exec_mode']
        self.workers_policy = self.config.get('workers_policy', 'permissive')  # by default not forcing the creation of all workers
        self.is_lithops_worker = is_lithops_worker()

        module_location = f'lithops.standalone.backends.{self.backend_name}'
        sb_module = importlib.import_module(module_location)
        StandaloneBackend = getattr(sb_module, 'StandaloneBackend')
        self.backend = StandaloneBackend(self.config[self.backend_name], self.exec_mode)

        self.jobs = []  # list to store executed jobs (job_keys)
        logger.debug("Standalone handler created successfully")

    def init(self):
        """
        Initialize the backend and create/start the master VM instance
        """
        self.backend.init()

    def _is_master_service_ready(self):
        """
        Checks if the proxy is ready to receive http connections
        """
        try:
            if self.is_lithops_worker:
                url = f"http://lithops-master:{SA_SERVICE_PORT}/ping"
                r = requests.get(url, timeout=1)
                if r.status_code == 200:
                    return True
                return False
            else:
                cmd = f'curl -X GET http://127.0.0.1:{SA_SERVICE_PORT}/ping'
                out = self.backend.master.get_ssh_client().run_remote_command(cmd)
                data = json.loads(out)
                if data['response'] == __version__:
                    return True
                else:
                    self.dismantle()
                    raise LithopsValidationError(
                        f"Lithops version {data['response']} on {self.backend.master}, "
                        f"doesn't match local lithops version {__version__}, consider "
                        "running 'lithops clean' to delete runtime  metadata leftovers or "
                        "'lithops clean --all' to delete master instance as well")
        except LithopsValidationError as e:
            raise e
        except Exception:
            return False

    def _validate_master_service_setup(self):
        """
        Checks the master VM is correctly installed
        """
        logger.debug(f'Validating lithops version installed on master matches {__version__}')

        ssh_client = self.backend.master.get_ssh_client()

        cmd = f'cat {SA_INSTALL_DIR}/access.data'
        res = ssh_client.run_remote_command(cmd)
        if not res:
            self.dismantle()
            raise LithopsValidationError(
                f"Lithops service not installed on {self.backend.master}, "
                "consider using 'lithops clean' to delete runtime metadata "
                "or 'lithops clean --all' to delete master instance as well")

        master_lithops_version = json.loads(res).get('lithops_version')
        if master_lithops_version != __version__:
            self.dismantle()
            raise LithopsValidationError(
                f"Lithops version {master_lithops_version} on {self.backend.master}, "
                f"doesn't match local lithops version {__version__}, consider "
                "running 'lithops clean' to delete runtime  metadata leftovers or "
                "'lithops clean --all' to delete master instance as well")

        logger.debug("Validating lithops lithops master service is "
                     f"running on {self.backend.master}")
        res = ssh_client.run_remote_command("service lithops-master status")
        if not res or 'Active: active (running)' not in res:
            self.dismantle()
            raise LithopsValidationError(
                f"Lithops master service not active on {self.backend.master}, "
                f"consider to delete master instance and metadata using "
                "'lithops clean --all'", res)
        # self.backend.master.del_ssh_client()  # Client is deleted in clear()

    def _wait_master_service_ready(self):
        """
        Waits until the proxy is ready to receive http connections
        """
        self._validate_master_service_setup()

        logger.info(f'Waiting Lithops service to become ready on {self.backend.master}')

        start = time.time()
        while (time.time() - start < self.start_timeout):
            if self._is_master_service_ready():
                ready_time = round(time.time() - start, 2)
                logger.debug(f'{self.backend.master} ready in {ready_time} seconds')
                return True
            time.sleep(2)

        self.dismantle()
        raise Exception(f'Lithops service readiness probe expired on {self.backend.master}')

    def _get_workers_on_master(self):
        """
        gets the total available workers on the master VM
        """
        workers_on_master = []
        try:
            if self.is_lithops_worker:
                url = f"http://lithops-master:{SA_SERVICE_PORT}/workers"
                resp = requests.get(url)
                workers_on_master = resp.json()
            else:
                cmd = (f'curl http://127.0.0.1:{SA_SERVICE_PORT}/workers '
                       '-H \'Content-Type: application/json\' -X GET')
                resp = self.backend.master.get_ssh_client().run_remote_command(cmd)
                workers_on_master = json.loads(resp)
        except LithopsValidationError as e:
            raise e
        except Exception:
            pass
        return workers_on_master

    def _wait_workers_ready(self, new_workers):
        """
        Wait a given set of workers to become ready
        """
        w_names = [w.name for w in new_workers]
        logger.info(f'Waiting following workers to become ready: {w_names}')

        start = time.time()
        workers_state_on_master = {}
        while (time.time() - start < self.start_timeout * 2):
            try:
                cmd = (f'curl -X GET http://127.0.0.1:{SA_SERVICE_PORT}/workers-state '
                       '-H \'Content-Type: application/json\'')
                resp = self.backend.master.get_ssh_client().run_remote_command(cmd)
                prev = workers_state_on_master

                workers_state_on_master = json.loads(resp)

                running = 0
                if prev != workers_state_on_master:

                    msg = 'All workers states: '
                    for w in workers_state_on_master:
                        w_state = workers_state_on_master[w]["state"]
                        msg += f'({w} - {w_state})'
                        if w in w_names and w_state == 'running':
                            if workers_state_on_master[w].get('err'):
                                logger.warning(f'Worker may operate not in desired '
                                               f'configuration, worker {w} error: '
                                               f'{workers_state_on_master[w].get("err")}')
                            running += 1

                    logger.info(msg)

                if running == len(w_names):
                    logger.info(f'All workers are ready: {w_names}')

                    # on backend, in case workers failed to get optimal workers setup, they may run
                    # but in order to notify user they will have running state, but 'err' containing error
                    for w in workers_state_on_master:
                        if w in w_names and workers_state_on_master[w]["state"] == 'running' \
                           and workers_state_on_master[w].get('err'):
                            logger.warning(f'Workers may operate not in desired configuration, '
                                           f'worker {w} error: {workers_state_on_master[w].get("err")}')
                    return

            except LithopsValidationError as e:
                raise e
            except Exception as e:
                pass

            time.sleep(10)

        raise Exception(f'Lithops workers service readiness probe expired on {self.backend.master}')

    def invoke(self, job_payload):
        """
        Run the job description against the selected environment
        """
        executor_id = job_payload['executor_id']
        job_id = job_payload['job_id']
        total_calls = job_payload['total_calls']
        chunksize = job_payload['chunksize']

        total_required_workers = (total_calls // chunksize + (total_calls % chunksize > 0)
                                  if self.exec_mode in [ExecMode.CREATE.value, ExecMode.REUSE.value] else 1)

        def create_workers(workers_to_create):
            current_workers_old = set(self.backend.workers)
            futures = []
            with cf.ThreadPoolExecutor(min(workers_to_create + 1, 48)) as ex:
                if not self._is_master_service_ready():
                    futures.append(ex.submit(lambda: self.backend.master.create(check_if_exists=True)))

                for vm_n in range(workers_to_create):
                    worker_id = "{:04d}".format(vm_n)
                    name = f'lithops-worker-{executor_id}-{job_id}-{worker_id}'
                    futures.append(ex.submit(self.backend.create_worker, name))

            for future in cf.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    # if workers policy is strict, raise exception in case failed to create all workers
                    if self.workers_policy == 'strict':
                        raise e

            current_workers_new = set(self.backend.workers)
            new_workers = current_workers_new - current_workers_old
            logger.debug("Total worker VM instances created: {}/{}"
                         .format(len(new_workers), workers_to_create))

            return list(new_workers)

        new_workers = []

        if self.exec_mode == ExecMode.CONSUME.value:
            total_workers = total_required_workers

        elif self.exec_mode == ExecMode.CREATE.value:
            new_workers = create_workers(total_required_workers)
            total_workers = len(new_workers)

        elif self.exec_mode == ExecMode.REUSE.value:
            workers = self._get_workers_on_master()
            total_workers = len(workers)
            logger.debug(f"Found {total_workers} free workers "
                         f"connected to master {self.backend.master}")
            if total_workers < total_required_workers:
                # create missing delta of workers
                workers_to_create = total_required_workers - total_workers
                logger.debug(f'Going to create {workers_to_create} new workers')
                new_workers = create_workers(workers_to_create)
                total_workers += len(new_workers)

        if total_workers == 0:
            raise Exception('It was not possible to create any worker')

        logger.debug(f'ExecutorID {executor_id} | JobID {job_id} - Going to run {total_calls} '
                     f'activations in {min(total_workers, total_required_workers)} workers')

        logger.debug(f"Checking if {self.backend.master} is ready")
        if not self._is_master_service_ready():
            self.backend.master.create(check_if_exists=True)
            self.backend.master.wait_ready()
            self._wait_master_service_ready()

        job_payload['worker_instances'] = [
            {'name': inst.name,
             'private_ip': inst.private_ip,
             'instance_id': inst.instance_id,
             'ssh_credentials': inst.ssh_credentials}
            for inst in new_workers
        ]

        # delete ssh key
        backend = job_payload['config']['lithops']['backend']
        job_payload['config'][backend].pop('ssh_key_filename', None)

        if self.is_lithops_worker:
            url = f"http://lithops-master:{SA_SERVICE_PORT}/run-job"
            requests.post(url, data=json.dumps(job_payload))
        else:
            pl = shlex.quote(json.dumps(job_payload))
            cmd = (f'curl http://127.0.0.1:{SA_SERVICE_PORT}/run-job -d {pl} '
                   '-H \'Content-Type: application/json\' -X POST')
            self.backend.master.get_ssh_client().run_remote_command(cmd)
            # self.backend.master.del_ssh_client()  # Client is deleted in clear()

        logger.debug('Job invoked on {}'.format(self.backend.master))

        self.jobs.append(job_payload['job_key'])

        # in case workers policy is strict, track all required workers create
        # in case of 'consume' mode there no new workers created
        if self.exec_mode != 'consume' and self.workers_policy == 'strict':
            threading.Thread(target=self._wait_workers_ready, args=(new_workers,), daemon=True).start()

    def deploy_runtime(self, runtime_name, *args):
        """
        Installs the proxy and extracts the runtime metadata
        """
        logger.debug(f'Checking if {self.backend.master} is ready')
        if not self.backend.master.is_ready():
            self.backend.master.create(check_if_exists=True)
            self.backend.master.wait_ready()

        self._setup_master_service()
        self._wait_master_service_ready()

        logger.debug('Extracting runtime metadata information')

        payload = {'runtime': runtime_name, 'pull_runtime': True}

        if self.is_lithops_worker:
            url = f"http://lithops-master:{SA_SERVICE_PORT}/get-metadata"
            resp = requests.get(url, data=json.dumps(payload))
            runtime_meta = resp.json()
        else:
            pl = shlex.quote(json.dumps(payload))
            cmd = (f'curl http://127.0.0.1:{SA_SERVICE_PORT}/get-metadata -d {pl} '
                   '-H \'Content-Type: application/json\' -X GET')
            out = self.backend.master.get_ssh_client().run_remote_command(cmd)
            runtime_meta = json.loads(out)

        return runtime_meta

    def dismantle(self):
        """
        Stop all VM instances
        """
        self.backend.dismantle()

    def clean(self, **kwargs):
        """
        Clan all the backend resources
        """
        self.backend.clean(**kwargs)

    def clear(self, job_keys=None):
        """
        Clear all the backend resources.
        clear method is executed after the results are get,
        when an exception is produced, or when a user press ctrl+c
        """
        try:
            if self.is_lithops_worker:
                url = f"http://lithops-master:{SA_SERVICE_PORT}/stop"
                requests.post(url, data=json.dumps(self.jobs))
            else:
                pl = shlex.quote(json.dumps(self.jobs))
                cmd = (f'curl http://127.0.0.1:{SA_SERVICE_PORT}/stop -d {pl} '
                       '-H \'Content-Type: application/json\' -X POST')
            self.backend.master.get_ssh_client().run_remote_command(cmd)
            self.backend.master.del_ssh_client()
        except Exception:
            pass

        if self.exec_mode != ExecMode.REUSE.value:
            self.backend.clear(job_keys)

    def get_runtime_key(self, runtime_name, runtime_memory, version=__version__):
        """
        Wrapper method that returns a formated string that represents the
        runtime key. Each backend has its own runtime key format. Used to
        store runtime metadata into the storage
        """
        return self.backend.get_runtime_key(runtime_name, version)

    def get_runtime_info(self):
        """
        Method that returns a dictionary with all the runtime information
        set in config
        """
        runtime_info = {
            'runtime_name': self.config['runtime'],
            'runtime_memory': None,
            'runtime_timeout': self.config['hard_dismantle_timeout'],
            'max_workers': self.config[self.backend_name]['max_workers'],
        }

        return runtime_info

    def get_backend_type(self):
        """
        Wrapper method that returns the type of the backend (Batch or FaaS)
        """
        return 'batch'

    def _setup_master_service(self):
        """
        Setup lithops necessary packages and files in master VM instance
        """
        logger.info(f'Installing Lithops in {self.backend.master}')

        ssh_client = self.backend.master.get_ssh_client()

        handler_zip = os.path.join(TEMP_DIR, 'lithops_standalone.zip')
        worker_path = os.path.join(os.path.dirname(__file__), 'worker.py')
        master_path = os.path.join(os.path.dirname(__file__), 'master.py')
        create_handler_zip(handler_zip, [master_path, worker_path])

        logger.debug('Uploading lithops files to {}'.format(self.backend.master))
        ssh_client.upload_local_file(handler_zip, '/tmp/lithops_standalone.zip')
        os.remove(handler_zip)

        vm_data = {'name': self.backend.master.name,
                   'instance_id': self.backend.master.get_instance_id(),
                   'private_ip': self.backend.master.get_private_ip(),
                   'delete_on_dismantle': self.backend.master.delete_on_dismantle,
                   'lithops_version': __version__}

        logger.debug('Executing lithops installation process on {}'.format(self.backend.master))
        logger.debug('Be patient, initial installation process may take up to 3 minutes')

        remote_script = "/tmp/install_lithops.sh"
        script = get_master_setup_script(self.config, vm_data)
        ssh_client.upload_data_to_file(script, remote_script)
        ssh_client.run_remote_command(f"chmod 777 {remote_script}; sudo {remote_script};")

        try:
            # Download the master VM public key generated with the installation script
            # This public key will be used to create to worker
            ssh_client.download_remote_file(
                f'{self.backend.master.home_dir}/.ssh/id_rsa.pub',
                f'{self.backend.cache_dir}/{self.backend.master.name}-id_rsa.pub')
        except FileNotFoundError:
            pass
