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

import signal
import logging
import math
import time
import concurrent.futures as cf
from functools import partial
from types import SimpleNamespace
from itertools import chain
from typing import Optional, List, Union, Tuple, Any

from lithops.utils import is_unix_system, timeout_handler, \
    is_notebook, is_lithops_worker, FuturesList
from lithops.storage import InternalStorage
from lithops.future import ResponseFuture
from lithops.monitor import JobMonitor


ALWAYS = 0
ANY_COMPLETED = -1
ALL_COMPLETED = 100

THREADPOOL_SIZE = 64
WAIT_DUR_SEC = 1

logger = logging.getLogger(__name__)


def wait(fs: Union[ResponseFuture, FuturesList, List[ResponseFuture]],
         internal_storage: Optional[InternalStorage] = None,
         job_monitor: Optional[JobMonitor] = None,
         throw_except: Optional[bool] = True,
         return_when: Optional[Any] = ALL_COMPLETED,
         download_results: Optional[bool] = False,
         timeout: Optional[int] = None,
         threadpool_size: Optional[int] = THREADPOOL_SIZE,
         wait_dur_sec: Optional[int] = WAIT_DUR_SEC,
         show_progressbar: Optional[bool] = True) -> Tuple[FuturesList, FuturesList]:
    """
    Wait for the Future instances (possibly created by different Executor instances)
    given by fs to complete. Returns a named 2-tuple of sets. The first set, named done,
    contains the futures that completed (finished or cancelled futures) before the wait
    completed. The second set, named not_done, contains the futures that did not complete
    (pending or running futures). timeout can be used to control the maximum number of
    seconds to wait before returning.

    :param fs: Futures list. Default None
    :param internal_storage: InternalStorage instance. Default None.
    :param job_monitor: JobMonitor instance. Default None.
    :param throw_except: Re-raise exception if call raised. Default True.
    :param return_when: Percentage of done futures
    :param download_results: Download results. Default false (Only get statuses)
    :param timeout: Timeout of waiting for results.
    :param threadpool_size: Number of threads to use. Default 64
    :param wait_dur_sec: Time interval between each check.
    :param show_progressbar: whether or not to show the progress bar.

    :return: `(fs_done, fs_notdone)`
        where `fs_done` is a list of futures that have completed
        and `fs_notdone` is a list of futures that have not completed.
    :rtype: 2-tuple of list
    """
    if not fs:
        return

    if type(fs) != list and type(fs) != FuturesList:
        fs = [fs]

    if download_results:
        fs_to_wait = len(fs)
        msg = (f'ExecutorID {fs[0].executor_id} - Getting results from {len(fs)} function activations')
        fs_done = [f for f in fs if f.done]
        fs_not_done = [f for f in fs if not f.done]

    else:
        fs_to_wait = math.ceil(return_when * len(fs) / 100)
        msg = (f'ExecutorID {fs[0].executor_id} - Waiting for {return_when}% of '
               f'{len(fs)} function activations to complete')
        fs_done = [f for f in fs if f.success or f.done]
        fs_not_done = [f for f in fs if not (f.success or f.done)]

    logger.info(msg)

    if not fs_not_done:
        return fs_done, fs_not_done

    if is_unix_system() and timeout is not None:
        logger.debug(f'Setting waiting timeout to {timeout} seconds')
        error_msg = 'Timeout of {timeout} seconds exceeded waiting for function activations to finish'
        signal.signal(signal.SIGALRM, partial(timeout_handler, error_msg))
        signal.alarm(timeout)

    # Setup progress bar
    pbar = None
    if not is_lithops_worker() and logger.getEffectiveLevel() == logging.INFO \
       and show_progressbar:
        from tqdm.auto import tqdm
        if not is_notebook():
            print()
        pbar = tqdm(bar_format='  {l_bar}{bar}| {n_fmt}/{total_fmt}  ',
                    total=fs_to_wait, disable=None)
        pbar.update(min(len(fs_done), fs_to_wait))

    try:
        executors_data = _create_executors_data_from_futures(fs, internal_storage)

        if not job_monitor:
            for executor_data in executors_data:
                job_monitor = JobMonitor(
                    executor_id=executor_data.executor_id,
                    internal_storage=executor_data.internal_storage)
                job_monitor.start(fs=executor_data.futures)

        sleep_sec = wait_dur_sec if job_monitor.backend == 'storage' else 0.3

        if return_when == ALWAYS:
            for executor_data in executors_data:
                _get_executor_data(fs, executor_data, pbar=pbar,
                                   throw_except=throw_except,
                                   download_results=download_results,
                                   threadpool_size=threadpool_size)
        else:
            while not _check_done(fs, return_when, download_results):
                for executor_data in executors_data:
                    new_data = _get_executor_data(fs, executor_data, pbar=pbar,
                                                  throw_except=throw_except,
                                                  download_results=download_results,
                                                  threadpool_size=threadpool_size)
                time.sleep(0 if new_data else sleep_sec)

    except KeyboardInterrupt as e:
        if download_results:
            not_dones_call_ids = [(f.job_id, f.call_id) for f in fs if not f.done]
        else:
            not_dones_call_ids = [(f.job_id, f.call_id) for f in fs if not f.success and not f.done]
        msg = ('Cancelled - Total Activations not done: {}'.format(len(not_dones_call_ids)))
        if pbar:
            pbar.close()
            print()
        logger.info(msg)
        raise e

    except Exception as e:
        raise e

    finally:
        if is_unix_system():
            signal.alarm(0)
        if pbar and not pbar.disable:
            pbar.close()
            if not is_notebook():
                print()

    if download_results:
        fs_done = [f for f in fs if f.done]
        fs_notdone = [f for f in fs if not f.done]
    else:
        fs_done = [f for f in fs if f.success or f.done]
        fs_notdone = [f for f in fs if not f.success and not f.done]

    return fs_done, fs_notdone


def get_result(fs: Optional[Union[ResponseFuture, FuturesList, List[ResponseFuture]]] = None,
               internal_storage: Optional[InternalStorage] = None,
               throw_except: Optional[bool] = True,
               timeout: Optional[int] = None,
               threadpool_size: Optional[int] = THREADPOOL_SIZE,
               wait_dur_sec: Optional[int] = WAIT_DUR_SEC,
               show_progressbar: Optional[bool] = True):
    """
    For getting the results from all function activations

    :param fs: Futures list. Default None
    :param internal_storage: InternalStorage instance. Default None.
    :param throw_except: Reraise exception if call raised. Default True.
    :param timeout: Timeout for waiting for results.
    :param threadpool_size: Number of threads to use. Default 128
    :param wait_dur_sec: Time interval between each check.
    :param show_progressbar: whether or not to show the progress bar.

    :return: The result of the future/s
    """
    if type(fs) != list and type(fs) != FuturesList:
        fs = [fs]

    fs_done, _ = wait(fs=fs, throw_except=throw_except,
                      timeout=timeout, download_results=True,
                      internal_storage=internal_storage,
                      threadpool_size=threadpool_size,
                      wait_dur_sec=wait_dur_sec,
                      show_progressbar=show_progressbar)
    result = []
    fs_done = [f for f in fs_done if not f.futures and f._produce_output]
    for f in fs_done:
        result.append(f.result(throw_except=throw_except))

    logger.debug("ExecutorID {} - Finished getting results".format(fs[0].executor_id))

    return result


def _create_executors_data_from_futures(fs, internal_storage):
    """
    Creates a dummy job necessary for the job monitor
    """
    executor_jobs = []
    present_executors = {f.executor_id for f in fs}

    for executor_id in present_executors:
        executor_data = SimpleNamespace()
        executor_data.executor_id = executor_id
        executor_data.futures = [f for f in fs if f.executor_id == executor_id]
        f = executor_data.futures[0]
        if internal_storage and internal_storage.backend == f._storage_config['backend']:
            executor_data.internal_storage = internal_storage
        else:
            executor_data.internal_storage = InternalStorage(f._storage_config)

        executor_jobs.append(executor_data)

    return executor_jobs


def _check_done(fs, return_when, download_results):
    """
    Checks if return_when% of futures are ready or done
    """
    if download_results:
        total_done = [f.done for f in fs].count(True)
    else:
        total_done = [f.success or f.done for f in fs].count(True)

    if return_when == ANY_COMPLETED:
        return total_done >= 1
    else:
        done_percentage = int(total_done * 100 / len(fs))
        return done_percentage >= return_when


def _get_executor_data(fs, exec_data, download_results, throw_except, threadpool_size, pbar):
    """
    Downloads all status/results from ready futures
    """

    if download_results:
        callids_done = [(f.executor_id, f.job_id, f.call_id) for f in exec_data.futures if (f.ready or f.success)]
        not_done_futures = [f for f in exec_data.futures if not f.done]
    else:
        callids_done = [(f.executor_id, f.job_id, f.call_id) for f in exec_data.futures if f.ready]
        not_done_futures = [f for f in exec_data.futures if not (f.success or f.done)]

    not_done_call_ids = set([(f.executor_id, f.job_id, f.call_id) for f in not_done_futures])
    new_callids_done = not_done_call_ids.intersection(callids_done)

    fs_to_wait_on = []
    for f in exec_data.futures:
        if (f.executor_id, f.job_id, f.call_id) in new_callids_done:
            fs_to_wait_on.append(f)

    def get_result(f):
        f.result(throw_except=throw_except, internal_storage=exec_data.internal_storage)

    def get_status(f):
        f.status(throw_except=throw_except, internal_storage=exec_data.internal_storage)

    pool = cf.ThreadPoolExecutor(max_workers=threadpool_size)
    if download_results:
        list(pool.map(get_result, fs_to_wait_on))
    else:
        list(pool.map(get_status, fs_to_wait_on))
    pool.shutdown()

    if pbar:
        for f in fs_to_wait_on:
            if (download_results and f.done) or \
               (not download_results and (f.success or f.done)):
                if pbar.n < pbar.total:
                    pbar.update(1)
        pbar.refresh()

    # Check for new futures
    new_futures = list(chain(*[f._new_futures for f in fs_to_wait_on if f._new_futures]))
    if new_futures:
        fs.extend(new_futures)
        exec_data.futures.extend(new_futures)
        if pbar:
            pbar.total = pbar.total + len(new_futures)
            pbar.refresh()

    return len(fs_to_wait_on)
