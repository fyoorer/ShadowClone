#
# Copyright 2018 PyWren Team
# Copyright IBM Corp. 2020
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
import sys
import time
import zlib
import base64
import pickle
import logging
import traceback
from six import reraise

from lithops.storage import InternalStorage
from lithops.storage.utils import check_storage_path, get_storage_path,\
    create_job_key
from lithops.constants import FN_LOG_FILE, LOGS_DIR

logger = logging.getLogger(__name__)


class ResponseFuture:
    """
    Object representing the result of a Lithops invocation. Returns the status of the
    execution and the result when available.
    """
    class State():
        New = "New"
        Invoked = "Invoked"
        Running = "Running"
        Ready = "Ready"
        Success = "Success"
        Futures = "Futures"
        Error = "Error"
        Done = "Done"

    GET_RESULT_SLEEP_SECS = 1
    GET_RESULT_MAX_RETRIES = 10

    def __init__(self, call_id, job, job_metadata, storage_config):
        self.call_id = call_id
        self.job_id = job.job_id
        self.job_key = job.job_key
        self.executor_id = job.executor_id
        self.function_name = job.function_name
        self.execution_timeout = job.execution_timeout
        self.runtime_name = job.runtime_name
        self.runtime_memory = job.runtime_memory
        self.activation_id = None
        self.stats = {}
        self.logs = None

        self._storage_config = storage_config
        self._produce_output = True
        self._read = False
        self._state = ResponseFuture.State.New
        self._exception = Exception()
        self._handler_exception = False
        self._new_futures = None
        self._traceback = None
        self._call_status = None
        self._call_output = None
        self._host_status_done_tstamp = None
        self._status_query_count = 0
        self._output_query_count = 0

        for key in job_metadata:
            if any(key.startswith(ss) for ss in ['func', 'host', 'worker']):
                self.stats[key] = job_metadata[key]

        self._storage_path = get_storage_path(self._storage_config)

    def _set_state(self, new_state):
        self._state = new_state

    def cancel(self):
        raise NotImplementedError("Cannot cancel dispatched jobs")

    def cancelled(self):
        raise NotImplementedError("Cannot cancel dispatched jobs")

    @property
    def new(self):
        return self._state == ResponseFuture.State.New

    @property
    def invoked(self):
        return self._state == ResponseFuture.State.Invoked

    @property
    def running(self):
        return self._state == ResponseFuture.State.Running

    @property
    def ready(self):
        return self._state in [ResponseFuture.State.Ready,
                               ResponseFuture.State.Futures]

    @property
    def error(self):
        return self._state == ResponseFuture.State.Error

    @property
    def futures(self):
        """
        The response of a call was a FutureResponse instance.
        It has to wait to the new invocation output.
        """
        return self._state == ResponseFuture.State.Futures

    @property
    def success(self):
        if self._state in [ResponseFuture.State.Success,
                           ResponseFuture.State.Error]:
            return True
        return False

    @property
    def done(self):
        if self._state in [ResponseFuture.State.Done,
                           ResponseFuture.State.Error]:
            return True
        return False

    def _set_invoked(self):
        """ Set the future as invoked"""
        self._state = ResponseFuture.State.Invoked

    def _set_running(self, call_status):
        """ Set the future as running"""
        self._call_status = call_status
        self.activation_id = self._call_status['activation_id']
        self._state = ResponseFuture.State.Running

    def _set_ready(self, call_status):
        """ Set the future as running"""
        self._call_status = call_status
        self._host_status_done_tstamp = time.time()
        self._state = ResponseFuture.State.Ready

    def _set_futures(self, call_status):
        """ Set the future as running"""
        self._call_status = call_status
        self._host_status_done_tstamp = time.time()
        self.status(throw_except=False)

    def status(self, throw_except=True, internal_storage=None, check_only=False):
        """
        Return the status returned by the call.
        If the call raised an exception, this method will raise the same exception
        If the future is cancelled before completing then CancelledError will be raised.

        :param check_only: Return None immediately if job is not complete. Default False.
        :param throw_except: Reraise exception if call raised. Default true.
        :param internal_storage: Storage handler to poll cloud storage. Default None.
        :return: Result of the call.
        :raises CancelledError: If the job is cancelled before completed.
        :raises TimeoutError: If job is not complete after `timeout` seconds.
        """
        if self._state == ResponseFuture.State.New:
            raise ValueError("task not yet invoked")

        if self.success or self.done:
            return self._call_status

        if self.ready and self._new_futures:
            self._set_state(ResponseFuture.State.Done)
            return self._call_status

        if self._call_status is None or self._call_status['type'] == '__init__':
            if internal_storage is None:
                internal_storage = InternalStorage(self._storage_config)
            check_storage_path(internal_storage.get_storage_config(), self._storage_path)
            self._call_status = internal_storage.get_call_status(self.executor_id, self.job_id, self.call_id)
            self._status_query_count += 1

            if check_only:
                return self._call_status

            while self._call_status is None:
                time.sleep(self.GET_RESULT_SLEEP_SECS)
                self._call_status = internal_storage.get_call_status(self.executor_id, self.job_id, self.call_id)
                self._status_query_count += 1
            self._host_status_done_tstamp = time.time()

        self.stats['host_status_done_tstamp'] = self._host_status_done_tstamp or time.time()
        self.stats['host_status_query_count'] = self._status_query_count
        self.activation_id = self._call_status['activation_id']

        if 'logs' in self._call_status:
            self.logs = zlib.decompress(base64.b64decode(self._call_status['logs'].encode())).decode()
            job_key = create_job_key(self.executor_id, self.job_id)
            log_file = os.path.join(LOGS_DIR, job_key + '.log')
            header = "Activation: '{}' ({})\n[\n".format(self.runtime_name, self.activation_id)
            tail = ']\n\n'
            output = self.logs.replace('\r', '').replace('\n', '\n    ', self.logs.count('\n') - 1)
            with open(log_file, 'a') as lf:
                lf.write(header + '    ' + output + tail)
            with open(FN_LOG_FILE, 'a') as lf:
                lf.write(header + '    ' + output + tail)

        if self._call_status['exception']:
            self._set_state(ResponseFuture.State.Error)
            self._exception = pickle.loads(eval(self._call_status['exc_info']))

            msg1 = ('ExecutorID {} | JobID {} - There was an exception - Activation '
                    'ID: {}'.format(self.executor_id, self.job_id, self.activation_id))

            if not self._call_status.get('exc_pickle_fail', False):
                fn_exctype = self._exception[0]
                fn_exc = self._exception[1]
                if fn_exc.args and fn_exc.args[0] == "HANDLER":
                    self._handler_exception = True
                    try:
                        del fn_exc.errno
                    except Exception:
                        pass
                    fn_exc.args = (fn_exc.args[1],)
            else:
                fn_exctype = Exception
                fn_exc = Exception(self._exception['exc_value'])
                self._exception = (fn_exctype, fn_exc,
                                   self._exception['exc_traceback'])

            def exception_hook(exctype, exc, trcbck):
                if exctype == fn_exctype and str(exc) == str(fn_exc):
                    logger.warning(msg1)
                    if self._handler_exception:
                        msg2 = 'Exception: {} - {}'.format(fn_exctype.__name__,
                                                           fn_exc)
                        logger.warning(msg2)
                    else:
                        traceback.print_exception(*self._exception)
                else:
                    sys.excepthook = sys.__excepthook__
                    traceback.print_exception(exctype, exc, trcbck)

            if throw_except:
                sys.excepthook = exception_hook
                reraise(*self._exception)
            else:
                logger.warning(msg1)
                msg2 = 'Exception: {} - {}'.format(self._exception[0].__name__,
                                                   self._exception[1])
                logger.warning(msg2)
                return None

        for key in self._call_status:
            if any(key.startswith(ss) for ss in ['func', 'host', 'worker']):
                self.stats[key] = self._call_status[key]

        self.stats['worker_exec_time'] = round(self.stats['worker_end_tstamp'] - self.stats['worker_start_tstamp'], 8)
        total_time = format(round(self.stats['worker_exec_time'], 2), '.2f')

        logger.debug(f'ExecutorID {self.executor_id} | JobID {self.job_id} - Got status from call {self.call_id} '
                     f'- Activation ID: {self.activation_id} - Time: {str(total_time)} seconds')

        self._set_state(ResponseFuture.State.Success)

        if self._call_status['func_result_size'] == 0:
            self._produce_output = False

        if not self._produce_output:
            self._set_state(ResponseFuture.State.Done)

        if 'new_futures' in self._call_status and not self._new_futures:
            new_futures = pickle.loads(eval(self._call_status['new_futures']))
            self._new_futures = [new_futures] if type(new_futures) == ResponseFuture else new_futures
            self._set_state(ResponseFuture.State.Futures)

        if 'result' in self._call_status:
            self._call_output = pickle.loads(eval(self._call_status['result']))
            self.stats['host_result_done_tstamp'] = time.time()
            self.stats['host_result_query_count'] = 0
            logger.debug(f'ExecutorID {self.executor_id} | JobID {self.job_id} - Got output '
                         f'from call {self.call_id} - Activation ID: {self.activation_id}')
            self._set_state(ResponseFuture.State.Done)

        return self._call_status

    def result(self, throw_except=True, internal_storage=None):
        """
        Return the value returned by the call.
        If the call raised an exception, this method will raise the same exception
        If the future is cancelled before completing then CancelledError will be raised.

        :param throw_except: Reraise exception if call raised. Default true.
        :param internal_storage: Storage handler to poll cloud storage. Default None.
        :return: Result of the call.
        :raises CancelledError: If the job is cancelled before completed.
        :raises TimeoutError: If job is not complete after `timeout` seconds.
        """
        if self._state == ResponseFuture.State.New:
            raise ValueError("Task not yet invoked")

        if not self._produce_output:
            self.status(throw_except=throw_except, internal_storage=internal_storage)
            self._set_state(ResponseFuture.State.Done)

        if self.done:
            return self._call_output

        if self._state == ResponseFuture.State.Futures:
            return self._new_futures

        if internal_storage is None:
            internal_storage = InternalStorage(storage_config=self._storage_config)

        self.status(throw_except=throw_except, internal_storage=internal_storage)

        if self.done:
            return self._call_output

        if self._call_output is None:
            call_output = internal_storage.get_call_output(self.executor_id, self.job_id, self.call_id)
            self._output_query_count += 1

            while call_output is None and self._output_query_count < self.GET_RESULT_MAX_RETRIES:
                time.sleep(self.GET_RESULT_SLEEP_SECS)
                call_output = internal_storage.get_call_output(self.executor_id, self.job_id, self.call_id)
                self._output_query_count += 1

            if call_output is None:
                if throw_except:
                    raise Exception(
                        f'ExecutorID {self.executor_id} | JobID {self.job_id} - Unable to get '
                        f'the result from call {self.call_id} - Activation ID: {self.activation_id}'
                    )
                else:
                    self._set_state(ResponseFuture.State.Error)
                    return None

            self._call_output = pickle.loads(call_output)

            self.stats['host_result_done_tstamp'] = time.time()
            self.stats['host_result_query_count'] = self._output_query_count
            logger.debug(f'ExecutorID {self.executor_id} | JobID {self.job_id} - Got output '
                         f'from call {self.call_id} - Activation ID: {self.activation_id}')

        self._set_state(ResponseFuture.State.Done)
        return self._call_output
