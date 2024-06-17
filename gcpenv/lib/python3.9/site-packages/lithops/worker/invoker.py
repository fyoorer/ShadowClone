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
import time
import logging
from types import SimpleNamespace

from lithops.serverless import ServerlessHandler
from lithops.monitor import JobMonitor
from lithops.storage import InternalStorage
from lithops.config import extract_serverless_config, extract_storage_config
from lithops.invokers import FaaSInvoker


logger = logging.getLogger(__name__)


def function_invoker(job_payload):
    """
    Method used as a remote invoker
    """
    config = job_payload['config']
    job = SimpleNamespace(**job_payload['job'])

    env = {'LITHOPS_WORKER': 'True', 'PYTHONUNBUFFERED': 'True',
           '__LITHOPS_SESSION_ID': job.job_key}
    os.environ.update(env)

    backend = config['lithops']['backend']
    config[backend]['invoke_pool_threads'] = 128

    # Create the internal_storage handler
    storage_config = extract_storage_config(config)
    internal_storage = InternalStorage(storage_config)

    # Create the compute handler
    serverless_config = extract_serverless_config(config)
    compute_handler = ServerlessHandler(serverless_config, storage_config)

    # Create the monitoring system
    monitoring_backend = config['lithops']['monitoring'].lower()
    monitoring_config = config.get(monitoring_backend)

    job_monitor = JobMonitor(
        executor_id=job.executor_id,
        internal_storage=internal_storage,
        backend=monitoring_backend,
        config=monitoring_config
    )

    # Create the invoker
    invoker = FaaSRemoteInvoker(
        config,
        job.executor_id,
        internal_storage,
        compute_handler,
        job_monitor
    )
    invoker.run_job(job)


class FaaSRemoteInvoker(FaaSInvoker):
    """
    Module responsible to perform the invocations against the serverless compute backend
    """

    def run_job(self, job):
        """
        Run a job
        """
        futures = self._run_job(job)
        self.job_monitor.start(
            fs=futures,
            job_id=job.job_id,
            chunksize=job.chunksize,
            generate_tokens=True
        )

        while self.pending_calls_q.qsize() > 0:
            time.sleep(1)

        self.job_monitor.stop()  # Stop job monitor thread
        self.stop()  # Stop async invokers threads
        time.sleep(5)

        logger.info('Remote Invoker Finished')
