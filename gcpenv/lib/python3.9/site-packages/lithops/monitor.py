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

import json
import pika
import logging
import time
import lithops
import pickle
import sys
import queue
import threading
import concurrent.futures as cf
from tblib import pickling_support
from lithops.constants import MONITORING_INTERVAL

pickling_support.install()

logger = logging.getLogger(__name__)

LOG_INTERVAL = 30  # Print monitor debug every LOG_INTERVAL seconds


class Monitor(threading.Thread):
    """
    Monitor base class
    """

    def __init__(self, executor_id,
                 internal_storage,
                 token_bucket_q,
                 generate_tokens,
                 config):

        super().__init__()
        self.executor_id = executor_id
        self.futures = []
        self.internal_storage = internal_storage
        self.should_run = True
        self.token_bucket_q = token_bucket_q
        self.generate_tokens = generate_tokens
        self.config = config
        self.daemon = True

        # vars for _generate_tokens
        self.workers = {}
        self.workers_done = []
        self.callids_done_worker = {}
        self.job_chunksize = {}
        self.present_jobs = set()

    def add_futures(self, fs, job_id=None, chunksize=None):
        """
        Extends the current thread list of futures to track
        """
        self.futures.extend(fs)

        # this is required for FaaS backends and _generate_tokens
        if job_id:
            self.job_chunksize[job_id] = chunksize

        present_jobs = {f.job_id for f in fs}
        for job_id in present_jobs:
            self.present_jobs.add(job_id)

    def _all_ready(self):
        """
        Checks if all futures are ready, success or done
        """
        return all([f.ready or f.success or f.done for f in self.futures])

    def _check_new_futures(self, call_status, f):
        """Checks if a functions returned new futures to track"""
        if 'new_futures' not in call_status:
            return False

        f._set_futures(call_status)
        self.futures.extend(f._new_futures)
        logger.debug(f'ExecutorID {self.executor_id} - Got {len(f._new_futures)} new futures to track')

        return True

    def _future_timeout_checker(self, futures):
        """
        Checks if running futures exceeded the timeout
        """
        current_time = time.time()
        futures_running = [f for f in futures if f.running]
        for fut in futures_running:
            try:
                start_tstamp = fut._call_status['worker_start_tstamp']
                fut_timeout = start_tstamp + fut.execution_timeout + 5
                if current_time > fut_timeout:
                    msg = 'The function did not run as expected.'
                    raise TimeoutError('HANDLER', msg)
            except TimeoutError:
                # generate fake TimeoutError call status
                pickled_exception = str(pickle.dumps(sys.exc_info()))
                call_status = {'type': '__end__',
                               'exception': True,
                               'exc_info': pickled_exception,
                               'executor_id': fut.executor_id,
                               'job_id': fut.job_id,
                               'call_id': fut.call_id,
                               'activation_id': fut.activation_id}
                fut._set_ready(call_status)

    def _print_status_log(self, previous_log=None, log_time=None):
        """prints a debug log showing the status of the job"""
        callids_pending = len([f for f in self.futures if f.invoked])
        callids_running = len([f for f in self.futures if f.running])
        callids_done = len([f for f in self.futures if f.ready or f.success or f.done])
        if (callids_pending, callids_running, callids_done) != previous_log or log_time > LOG_INTERVAL:
            logger.debug(f'ExecutorID {self.executor_id} - Pending: {callids_pending} '
                         f'- Running: {callids_running} - Done: {callids_done}')
            log_time = 0
        return (callids_pending, callids_running, callids_done), log_time


class RabbitmqMonitor(Monitor):

    def __init__(self, executor_id, internal_storage, token_bucket_q, generate_tokens, config):
        super().__init__(executor_id, internal_storage, token_bucket_q, generate_tokens, config)

        self.rabbit_amqp_url = config.get('amqp_url')
        self.queue = f'lithops-{self.executor_id}'
        self._create_resources()

    def _create_resources(self):
        """
        Creates RabbitMQ queues and exchanges of a given job
        """
        logger.debug(f'ExecutorID {self.executor_id} - Creating RabbitMQ queue {self.queue}')

        self.pikaparams = pika.URLParameters(self.rabbit_amqp_url)
        self.connection = pika.BlockingConnection(self.pikaparams)
        channel = self.connection.channel()
        channel.queue_declare(queue=self.queue, auto_delete=True)
        channel.close()

    def _delete_resources(self):
        """
        Deletes RabbitMQ queues and exchanges of a given job.
        """
        connection = pika.BlockingConnection(self.pikaparams)
        channel = connection.channel()
        channel.queue_delete(queue=self.queue)
        channel.close()
        connection.close()

    def stop(self):
        """
        Stops the monitor thread
        """
        self.should_run = False
        self._delete_resources()

    def _tag_future_as_running(self, call_status):
        """
        Assigns a call_status to its future
        """
        not_running_futures = [f for f in self.futures if not (f.running or f.ready or f.success or f.done)]
        for f in not_running_futures:
            calljob_id = (call_status['executor_id'], call_status['job_id'], call_status['call_id'])
            if (f.executor_id, f.job_id, f.call_id) == calljob_id:
                f._set_running(call_status)

    def _tag_future_as_ready(self, call_status):
        """
        tags a future as ready based on call_status
        """
        not_ready_futures = [f for f in self.futures if not (f.ready or f.success or f.done)]
        for f in not_ready_futures:
            calljob_id = (call_status['executor_id'], call_status['job_id'], call_status['call_id'])
            if (f.executor_id, f.job_id, f.call_id) == calljob_id:
                if not self._check_new_futures(call_status, f):
                    f._set_ready(call_status)

    def _generate_tokens(self, call_status):
        """
        generates a new token for the invoker
        """
        if not self.generate_tokens or not self.should_run:
            return

        call_id = (call_status['executor_id'], call_status['job_id'], call_status['call_id'])
        worker_id = call_status['activation_id']
        if worker_id not in self.callids_done_worker:
            self.callids_done_worker[worker_id] = []
        self.callids_done_worker[worker_id].append(call_id)

        if worker_id not in self.workers_done and \
                len(self.callids_done_worker[worker_id]) == call_status['chunksize']:
            self.workers_done.append(worker_id)
            if self.should_run:
                self.token_bucket_q.put('#')

    def run(self):
        logger.debug(f'ExecutorID {self.executor_id} |  Starting RabbitMQ job monitor')
        prevoius_log = None
        log_time = 0
        SLEEP_TIME = 2

        channel = self.connection.channel()

        def callback(ch, method, properties, body):
            call_status = json.loads(body.decode("utf-8"))

            if call_status['type'] == '__init__':
                self._tag_future_as_running(call_status)

            elif call_status['type'] == '__end__':
                self._generate_tokens(call_status)
                self._tag_future_as_ready(call_status)

            if self._all_ready() or not self.should_run:
                ch.stop_consuming()
                ch.close()
                self._print_status_log()
                logger.debug(f'ExecutorID {self.executor_id} | RabbitMQ job monitor finished')

        channel.basic_consume(self.queue, callback, auto_ack=True)
        threading.Thread(target=channel.start_consuming, daemon=True).start()

        while not self._all_ready() or not self.futures:
            # Format call_ids running, pending and done
            prevoius_log, log_time = self._print_status_log(previous_log=prevoius_log, log_time=log_time)
            self._future_timeout_checker(self.futures)
            time.sleep(SLEEP_TIME)
            log_time += SLEEP_TIME

            if not self.should_run:
                break


class StorageMonitor(Monitor):
    THREADPOOL_SIZE = 64

    def __init__(self, executor_id, internal_storage, token_bucket_q, generate_tokens, config):
        super().__init__(executor_id, internal_storage, token_bucket_q, generate_tokens, config)

        self.monitoring_interval = config['monitoring_interval']

        # vars for _generate_tokens
        self.callids_running_worker = {}
        self.callids_running_processed = set()
        self.callids_done_processed = set()

        # vars for _mark_status_as_running
        self.callids_running_processed_timeout = set()

        # vars for _mark_status_as_ready
        self.callids_done_processed_status = set()

    def stop(self):
        """
        Stops the monitor thread
        """
        self.should_run = False

    def _tag_future_as_running(self, callids_running):
        """
        Mark which futures are in running status based on callids_running
        """
        current_time = time.time()
        not_running_futures = [f for f in self.futures if not (f.running or f.ready or f.success or f.done)]
        callids_running_to_process = callids_running - self.callids_running_processed_timeout
        for f in not_running_futures:
            for call in callids_running_to_process:
                if f.invoked and (f.executor_id, f.job_id, f.call_id) == call[0]:
                    call_status = {'type': '__init__',
                                   'activation_id': call[1],
                                   'worker_start_tstamp': current_time}
                    f._set_running(call_status)

        self.callids_running_processed_timeout.update(callids_running_to_process)
        self._future_timeout_checker(self.futures)

    def _tag_future_as_ready(self, callids_done):
        """
        Mark which futures has a call_status ready to be downloaded
        """
        not_ready_futures = [f for f in self.futures if not (f.ready or f.success or f.done)]
        callids_done_to_process = callids_done - self.callids_done_processed_status
        fs_to_query = []

        ten_percent = int(len(self.futures) * (10 / 100))
        if len(self.futures) - len(callids_done) <= max(10, ten_percent):
            fs_to_query = not_ready_futures
        else:
            for f in not_ready_futures:
                if (f.executor_id, f.job_id, f.call_id) in callids_done_to_process:
                    fs_to_query.append(f)

        if not fs_to_query:
            return

        def get_status(f):
            cs = self.internal_storage.get_call_status(f.executor_id, f.job_id, f.call_id)
            f._status_query_count += 1
            if cs:
                if not self._check_new_futures(cs, f):
                    f._set_ready(cs)
                return (f.executor_id, f.job_id, f.call_id)
            else:
                return None

        try:
            pool = cf.ThreadPoolExecutor(max_workers=self.THREADPOOL_SIZE)
            call_ids_processed = set(pool.map(get_status, fs_to_query))
            pool.shutdown()
        except Exception:
            pass

        try:
            call_ids_processed.remove(None)
        except Exception:
            pass

        try:
            self.callids_done_processed_status.update(call_ids_processed)
        except Exception:
            pass

    def _generate_tokens(self, callids_running, callids_done):
        """
        Method that generates new tokens
        """
        if not self.generate_tokens or not self.should_run:
            return

        callids_running_to_process = callids_running - self.callids_running_processed
        callids_done_to_process = callids_done - self.callids_done_processed

        for call_id, worker_id in callids_running_to_process:
            if worker_id not in self.workers:
                self.workers[worker_id] = set()
            self.workers[worker_id].add(call_id)
            self.callids_running_worker[call_id] = worker_id

        for callid_done in callids_done_to_process:
            if callid_done in self.callids_running_worker:
                worker_id = self.callids_running_worker[callid_done]
                if worker_id not in self.callids_done_worker:
                    self.callids_done_worker[worker_id] = []
                self.callids_done_worker[worker_id].append(callid_done)

        for worker_id in self.callids_done_worker:
            job_id = self.callids_done_worker[worker_id][0][1]
            if job_id not in self.present_jobs:
                continue
            chunksize = self.job_chunksize[job_id]
            if worker_id not in self.workers_done and \
                    len(self.callids_done_worker[worker_id]) == chunksize:
                self.workers_done.append(worker_id)
                if self.should_run:
                    self.token_bucket_q.put('#')
                else:
                    break

        self.callids_running_processed.update(callids_running_to_process)
        self.callids_done_processed.update(callids_done_to_process)

    def run(self):
        """
        Run method
        """
        logger.debug(f'ExecutorID {self.executor_id} - Starting Storage job monitor')

        WAIT_DUR_SEC = self.monitoring_interval
        prevoius_log = None
        log_time = 0

        while not self._all_ready() or not self.futures:
            time.sleep(WAIT_DUR_SEC)
            WAIT_DUR_SEC = self.monitoring_interval
            log_time += WAIT_DUR_SEC

            if not self.should_run:
                break

            callids_running, callids_done = \
                self.internal_storage.get_job_status(self.executor_id)

            # verify if there are new callids_done and reduce the sleep
            new_callids_done = callids_done - self.callids_done_processed_status
            if len(new_callids_done) > 0:
                WAIT_DUR_SEC = 0.5

            # generate tokens and mark futures as running/done
            self._generate_tokens(callids_running, callids_done)
            self._tag_future_as_running(callids_running)
            self._tag_future_as_ready(callids_done)
            prevoius_log, log_time = self._print_status_log(prevoius_log, log_time)

        logger.debug(f'ExecutorID {self.executor_id} - Storage job monitor finished')


class JobMonitor:

    def __init__(self, executor_id, internal_storage, config=None):
        self.executor_id = executor_id
        self.internal_storage = internal_storage
        self.config = config
        self.backend = self.config['lithops']['monitoring'].lower() if config else 'storage'
        self.token_bucket_q = queue.Queue()
        self.monitor = None

        self.MonitorClass = getattr(
            lithops.monitor,
            f'{self.backend.capitalize()}Monitor'
        )

    def start(self, fs, job_id=None, chunksize=None, generate_tokens=False):
        if self.backend == 'storage':
            mi = self.config['lithops'].get('monitoring_interval', MONITORING_INTERVAL) \
                if self.config else MONITORING_INTERVAL
            bk_config = {'monitoring_interval': mi}
        else:
            bk_config = self.config.get(self.backend)

        if not self.monitor or not self.monitor.is_alive():
            self.monitor = self.MonitorClass(
                executor_id=self.executor_id,
                internal_storage=self.internal_storage,
                token_bucket_q=self.token_bucket_q,
                generate_tokens=generate_tokens,
                config=bk_config
            )
            self.monitor.start()
        self.monitor.add_futures(fs, job_id, chunksize)

    def stop(self):
        if self.monitor and self.monitor.is_alive():
            self.monitor.stop()
