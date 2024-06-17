#
# (C) Copyright IBM Corp. 2020
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
import sys
import copy
import logging
import atexit
import pickle
import tempfile
import subprocess as sp
from typing import Optional, List, Union, Tuple, Dict, Any
from collections.abc import Callable
from datetime import datetime

from lithops import constants
from lithops.future import ResponseFuture
from lithops.invokers import create_invoker
from lithops.storage import InternalStorage
from lithops.wait import wait, ALL_COMPLETED, THREADPOOL_SIZE, WAIT_DUR_SEC, ALWAYS
from lithops.job import create_map_job, create_reduce_job
from lithops.config import default_config, \
    extract_localhost_config, extract_standalone_config, \
    extract_serverless_config, get_log_info, extract_storage_config
from lithops.constants import LOCALHOST, CLEANER_DIR, \
    SERVERLESS, STANDALONE
from lithops.utils import is_notebook, setup_lithops_logger, \
    is_lithops_worker, create_executor_id, create_futures_list
from lithops.localhost.localhost import LocalhostHandler
from lithops.standalone.standalone import StandaloneHandler
from lithops.serverless.serverless import ServerlessHandler
from lithops.storage.utils import create_job_key, CloudObject
from lithops.monitor import JobMonitor
from lithops.utils import FuturesList


logger = logging.getLogger(__name__)
CLEANER_PROCESS = None


class FunctionExecutor:
    """
    Executor abstract class that contains the common logic for the Localhost, Serverless and Standalone executors

    :param mode: Execution mode. One of: localhost, serverless or standalone
    :param config: Settings passed in here will override those in lithops_config
    :param backend: Compute backend to run the functions
    :param storage: Storage backend to store Lithops data
    :param runtime: Name of the runtime to run the functions
    :param runtime_memory: Memory (in MB) to use to run the functions
    :param monitoring: Monitoring system implementation. One of: storage, rabbitmq
    :param max_workers: Max number of parallel workers
    :param worker_processes: Worker granularity, number of concurrent/parallel processes in each worker
    :param remote_invoker: Spawn a function that will perform the actual job invocation (True/False)
    :param log_level: Log level printing (INFO, DEBUG, ...). Set it to None to hide all logs. If this is param is set, all logging params in config are disabled
    """

    def __init__(
        self,
        mode: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
        backend: Optional[str] = None,
        storage: Optional[str] = None,
        runtime: Optional[str] = None,
        runtime_memory: Optional[int] = None,
        monitoring: Optional[str] = None,
        max_workers: Optional[int] = None,
        worker_processes: Optional[int] = None,
        remote_invoker: Optional[bool] = None,
        log_level: Optional[str] = False
    ):
        self.is_lithops_worker = is_lithops_worker()
        self.executor_id = create_executor_id()
        self.futures = []
        self.cleaned_jobs = set()
        self.total_jobs = 0
        self.last_call = None

        # setup lithops logging
        if not self.is_lithops_worker:
            # if is lithops worker, logging has been set up in entry_point.py
            if log_level:
                setup_lithops_logger(log_level)
            elif log_level is False and logger.getEffectiveLevel() == logging.WARNING:
                # Set default logging from config
                setup_lithops_logger(*get_log_info(config))

        # overwrite user-provided parameters
        config_ow = {'lithops': {}, 'backend': {}}
        if runtime is not None:
            config_ow['backend']['runtime'] = runtime
        if runtime_memory is not None:
            config_ow['backend']['runtime_memory'] = int(runtime_memory)
        if remote_invoker is not None:
            config_ow['backend']['remote_invoker'] = remote_invoker
        if worker_processes is not None:
            config_ow['backend']['worker_processes'] = worker_processes
        if max_workers is not None:
            config_ow['backend']['max_workers'] = max_workers

        if mode is not None:
            config_ow['lithops']['mode'] = mode
        if backend is not None:
            config_ow['lithops']['backend'] = backend
        if storage is not None:
            config_ow['lithops']['storage'] = storage
        if monitoring is not None:
            config_ow['lithops']['monitoring'] = monitoring

        # Load configuration
        self.config = default_config(copy.deepcopy(config), config_ow)

        self.data_cleaner = self.config['lithops'].get('data_cleaner', True)
        if self.data_cleaner and not self.is_lithops_worker:
            atexit.register(self.clean, clean_cloudobjects=False, clean_fn=True)

        storage_config = extract_storage_config(self.config)
        self.internal_storage = InternalStorage(storage_config)
        self.storage = self.internal_storage.storage

        self.backend = self.config['lithops']['backend']
        self.mode = self.config['lithops']['mode']

        if self.mode == LOCALHOST:
            localhost_config = extract_localhost_config(self.config)
            self.compute_handler = LocalhostHandler(localhost_config)
        elif self.mode == SERVERLESS:
            serverless_config = extract_serverless_config(self.config)
            self.compute_handler = ServerlessHandler(serverless_config, self.internal_storage)
        elif self.mode == STANDALONE:
            standalone_config = extract_standalone_config(self.config)
            self.compute_handler = StandaloneHandler(standalone_config)

        # Create the monitoring system
        self.job_monitor = JobMonitor(
            executor_id=self.executor_id,
            internal_storage=self.internal_storage,
            config=self.config
        )

        # Create the invoker
        self.invoker = create_invoker(
            config=self.config,
            executor_id=self.executor_id,
            internal_storage=self.internal_storage,
            compute_handler=self.compute_handler,
            job_monitor=self.job_monitor
        )

        logger.debug(f'Function executor for {self.backend} created with ID: {self.executor_id}')

        self.log_path = None

    def __enter__(self):
        """ Context manager method """
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """ Context manager method """
        self.job_monitor.stop()
        self.invoker.stop()
        self.compute_handler.clear()

    def _create_job_id(self, call_type):
        job_id = str(self.total_jobs).zfill(3)
        self.total_jobs += 1
        return '{}{}'.format(call_type, job_id)

    def call_async(
        self,
        func: Callable,
        data: Union[List[Any], Tuple[Any, ...], Dict[str, Any]],
        extra_env: Optional[Dict] = None,
        runtime_memory: Optional[int] = None,
        timeout: Optional[int] = None,
        include_modules: Optional[List] = [],
        exclude_modules: Optional[List] = []
    ) -> ResponseFuture:
        """
        For running one function execution asynchronously.

        :param func: The function to map over the data.
        :param data: Input data. Arguments can be passed as a list or tuple, or as a dictionary for keyword arguments.
        :param extra_env: Additional env variables for function environment.
        :param runtime_memory: Memory to use to run the function.
        :param timeout: Time that the function has to complete its execution before raising a timeout.
        :param include_modules: Explicitly pickle these dependencies.
        :param exclude_modules: Explicitly keep these modules from pickled dependencies.

        :return: Response future.
        """
        job_id = self._create_job_id('A')
        self.last_call = 'call_async'

        runtime_meta = self.invoker.select_runtime(job_id, runtime_memory)

        job = create_map_job(config=self.config,
                             internal_storage=self.internal_storage,
                             executor_id=self.executor_id,
                             job_id=job_id,
                             map_function=func,
                             iterdata=[data],
                             runtime_meta=runtime_meta,
                             runtime_memory=runtime_memory,
                             extra_env=extra_env,
                             include_modules=include_modules,
                             exclude_modules=exclude_modules,
                             execution_timeout=timeout)

        futures = self.invoker.run_job(job)
        self.futures.extend(futures)

        return futures[0]

    def map(
        self,
        map_function: Callable,
        map_iterdata: List[Union[List[Any], Tuple[Any, ...], Dict[str, Any]]],
        chunksize: Optional[int] = None,
        extra_args: Optional[Union[List[Any], Tuple[Any, ...], Dict[str, Any]]] = None,
        extra_env: Optional[Dict[str, str]] = None,
        runtime_memory: Optional[int] = None,
        obj_chunk_size: Optional[int] = None,
        obj_chunk_number: Optional[int] = None,
        obj_newline: Optional[str] = '\n',
        timeout: Optional[int] = None,
        include_modules: Optional[List[str]] = [],
        exclude_modules: Optional[List[str]] = []
    ) -> FuturesList:
        """
        Spawn multiple function activations based on the items of an input list.

        :param map_function: The function to map over the data
        :param map_iterdata: An iterable of input data (e.g python list).
        :param chunksize: Split map_iteradata in chunks of this size. Lithops spawns 1 worker per resulting chunk
        :param extra_args: Additional arguments to pass to each map_function activation
        :param extra_env: Additional environment variables for function environment
        :param runtime_memory: Memory (in MB) to use to run the functions
        :param obj_chunk_size: Used for data processing. Chunk size to split each object in bytes. Must be >= 1MiB. 'None' for processing the whole file in one function activation
        :param obj_chunk_number: Used for data processing. Number of chunks to split each object. 'None' for processing the whole file in one function activation. chunk_n has prevalence over chunk_size if both parameters are set
        :param obj_newline: new line character for keeping line integrity of partitions. 'None' for disabling line integrity logic and get partitions of the exact same size in the functions
        :param timeout: Max time per function activation (seconds)
        :param include_modules: Explicitly pickle these dependencies. All required dependencies are pickled if default empty list. No one dependency is pickled if it is explicitly set to None
        :param exclude_modules: Explicitly keep these modules from pickled dependencies. It is not taken into account if you set include_modules.

        :return: A list with size `len(map_iterdata)` of futures for each job (Futures are also internally stored by Lithops).
        """

        job_id = self._create_job_id('M')
        self.last_call = 'map'

        runtime_meta = self.invoker.select_runtime(job_id, runtime_memory)

        job = create_map_job(
            config=self.config,
            internal_storage=self.internal_storage,
            executor_id=self.executor_id,
            job_id=job_id,
            map_function=map_function,
            iterdata=map_iterdata,
            chunksize=chunksize,
            runtime_meta=runtime_meta,
            runtime_memory=runtime_memory,
            extra_env=extra_env,
            include_modules=include_modules,
            exclude_modules=exclude_modules,
            execution_timeout=timeout,
            extra_args=extra_args,
            obj_chunk_size=obj_chunk_size,
            obj_chunk_number=obj_chunk_number,
            obj_newline=obj_newline
        )

        futures = self.invoker.run_job(job)
        self.futures.extend(futures)

        if isinstance(map_iterdata, FuturesList):
            for fut in map_iterdata:
                fut._produce_output = False

        return create_futures_list(futures, self)

    def map_reduce(
        self,
        map_function: Callable,
        map_iterdata: List[Union[List[Any], Tuple[Any, ...], Dict[str, Any]]],
        reduce_function: Callable,
        chunksize: Optional[int] = None,
        extra_args: Optional[Union[List[Any], Tuple[Any, ...], Dict[str, Any]]] = None,
        extra_args_reduce: Optional[Union[List[Any], Tuple[Any, ...], Dict[str, Any]]] = None,
        extra_env: Optional[Dict[str, str]] = None,
        map_runtime_memory: Optional[int] = None,
        reduce_runtime_memory: Optional[int] = None,
        timeout: Optional[int] = None,
        obj_chunk_size: Optional[int] = None,
        obj_chunk_number: Optional[int] = None,
        obj_newline: Optional[str] = '\n',
        obj_reduce_by_key: Optional[bool] = False,
        spawn_reducer: Optional[int] = 20,
        include_modules: Optional[List[str]] = [],
        exclude_modules: Optional[List[str]] = []
    ) -> FuturesList:
        """
        Map the map_function over the data and apply the reduce_function across all futures.

        :param map_function: The function to map over the data
        :param map_iterdata: An iterable of input data
        :param reduce_function: The function to reduce over the futures
        :param chunksize: Split map_iteradata in chunks of this size. Lithops spawns 1 worker per resulting chunk. Default 1
        :param extra_args: Additional arguments to pass to function activation. Default None
        :param extra_args_reduce: Additional arguments to pass to the reduce function activation. Default None
        :param extra_env: Additional environment variables for action environment. Default None
        :param map_runtime_memory: Memory to use to run the map function. Default None (loaded from config)
        :param reduce_runtime_memory: Memory to use to run the reduce function. Default None (loaded from config)
        :param timeout: Time that the functions have to complete their execution before raising a timeout
        :param obj_chunk_size: the size of the data chunks to split each object. 'None' for processing the whole file in one function activation
        :param obj_chunk_number: Number of chunks to split each object. 'None' for processing the whole file in one function activation
        :param obj_newline: New line character for keeping line integrity of partitions. 'None' for disabling line integrity logic and get partitions of the exact same size in the functions
        :param obj_reduce_by_key: Set one reducer per object after running the partitioner. By default there is one reducer for all the objects
        :param spawn_reducer: Percentage of done map functions before spawning the reduce function
        :param include_modules: Explicitly pickle these dependencies.
        :param exclude_modules: Explicitly keep these modules from pickled dependencies.

        :return: A list with size `len(map_iterdata)` of futures.
        """
        self.last_call = 'map_reduce'
        map_job_id = self._create_job_id('M')

        runtime_meta = self.invoker.select_runtime(map_job_id, map_runtime_memory)

        map_job = create_map_job(
            config=self.config,
            internal_storage=self.internal_storage,
            executor_id=self.executor_id,
            job_id=map_job_id,
            map_function=map_function,
            iterdata=map_iterdata,
            chunksize=chunksize,
            runtime_meta=runtime_meta,
            runtime_memory=map_runtime_memory,
            extra_args=extra_args,
            extra_env=extra_env,
            obj_chunk_size=obj_chunk_size,
            obj_chunk_number=obj_chunk_number,
            obj_newline=obj_newline,
            include_modules=include_modules,
            exclude_modules=exclude_modules,
            execution_timeout=timeout
        )

        map_futures = self.invoker.run_job(map_job)
        self.futures.extend(map_futures)

        if isinstance(map_iterdata, FuturesList):
            for fut in map_iterdata:
                fut._produce_output = False

        if spawn_reducer != ALWAYS:
            self.wait(map_futures, return_when=spawn_reducer)
            logger.debug(f'ExecutorID {self.executor_id} | JobID {map_job_id} - '
                         f'{spawn_reducer}% of map activations done. Spawning reduce stage')

        reduce_job_id = map_job_id.replace('M', 'R')

        runtime_meta = self.invoker.select_runtime(reduce_job_id, reduce_runtime_memory)

        reduce_job = create_reduce_job(
            config=self.config,
            internal_storage=self.internal_storage,
            executor_id=self.executor_id,
            reduce_job_id=reduce_job_id,
            reduce_function=reduce_function,
            map_job=map_job,
            map_futures=map_futures,
            runtime_meta=runtime_meta,
            runtime_memory=reduce_runtime_memory,
            extra_args=extra_args_reduce,
            obj_reduce_by_key=obj_reduce_by_key,
            extra_env=extra_env,
            include_modules=include_modules,
            exclude_modules=exclude_modules
        )

        reduce_futures = self.invoker.run_job(reduce_job)
        self.futures.extend(reduce_futures)

        for f in map_futures:
            f._produce_output = False

        return create_futures_list(map_futures + reduce_futures, self)

    def wait(
        self,
        fs: Optional[Union[ResponseFuture, FuturesList, List[ResponseFuture]]] = None,
        throw_except: Optional[bool] = True,
        return_when: Optional[Any] = ALL_COMPLETED,
        download_results: Optional[bool] = False,
        timeout: Optional[int] = None,
        threadpool_size: Optional[int] = THREADPOOL_SIZE,
        wait_dur_sec: Optional[int] = WAIT_DUR_SEC,
        show_progressbar: Optional[bool] = True
    ) -> Tuple[FuturesList, FuturesList]:
        """
        Wait for the Future instances (possibly created by different Executor instances)
        given by fs to complete. Returns a named 2-tuple of sets. The first set, named done,
        contains the futures that completed (finished or cancelled futures) before the wait
        completed. The second set, named not_done, contains the futures that did not complete
        (pending or running futures). timeout can be used to control the maximum number of
        seconds to wait before returning.

        :param fs: Futures list. Default None
        :param throw_except: Re-raise exception if call raised. Default True
        :param return_when: Percentage of done futures
        :param download_results: Download results. Default false (Only get statuses)
        :param timeout: Timeout of waiting for results
        :param threadpool_size: Number of threads to use. Default 64
        :param wait_dur_sec: Time interval between each check
        :param show_progressbar: whether or not to show the progress bar.

        :return: `(fs_done, fs_notdone)` where `fs_done` is a list of futures that have completed and `fs_notdone` is a list of futures that have not completed.
        """
        futures = fs or self.futures
        if type(futures) != list and type(futures) != FuturesList:
            futures = [futures]

        # Start waiting for results
        try:
            wait(fs=futures,
                 internal_storage=self.internal_storage,
                 job_monitor=self.job_monitor,
                 download_results=download_results,
                 throw_except=throw_except,
                 return_when=return_when,
                 timeout=timeout,
                 threadpool_size=threadpool_size,
                 wait_dur_sec=wait_dur_sec,
                 show_progressbar=show_progressbar)

            if self.data_cleaner and return_when == ALL_COMPLETED:
                present_jobs = {f.job_key for f in futures}
                self.compute_handler.clear(present_jobs)
                self.clean(clean_cloudobjects=False)

        except (KeyboardInterrupt, Exception) as e:
            self.invoker.stop()
            self.job_monitor.stop()
            if not fs and is_notebook():
                del self.futures[len(self.futures) - len(futures):]
            if self.data_cleaner:
                present_jobs = {f.job_key for f in futures}
                self.compute_handler.clear(present_jobs)
                self.clean(clean_cloudobjects=False, force=True)
            raise e

        if download_results:
            fs_done = [f for f in futures if f.done]
            fs_notdone = [f for f in futures if not f.done]
        else:
            fs_done = [f for f in futures if f.success or f.done]
            fs_notdone = [f for f in futures if not f.success and not f.done]

        return create_futures_list(fs_done, self), create_futures_list(fs_notdone, self)

    def get_result(
        self,
        fs: Optional[Union[ResponseFuture, FuturesList, List[ResponseFuture]]] = None,
        throw_except: Optional[bool] = True,
        timeout: Optional[int] = None,
        threadpool_size: Optional[int] = THREADPOOL_SIZE,
        wait_dur_sec: Optional[int] = WAIT_DUR_SEC,
        show_progressbar: Optional[bool] = True
    ):
        """
        For getting the results from all function activations

        :param fs: Futures list. Default None
        :param throw_except: Reraise exception if call raised. Default True.
        :param timeout: Timeout for waiting for results.
        :param threadpool_size: Number of threads to use. Default 128
        :param wait_dur_sec: Time interval between each check.
        :param show_progressbar: whether or not to show the progress bar.

        :return: The result of the future/s
        """
        fs_done, _ = self.wait(
            fs=fs,
            throw_except=throw_except,
            timeout=timeout,
            download_results=True,
            threadpool_size=threadpool_size,
            wait_dur_sec=wait_dur_sec,
            show_progressbar=show_progressbar
        )

        result = []
        fs_done = [f for f in fs_done if not f.futures and f._produce_output]
        for f in fs_done:
            if fs:
                # Process futures provided by the user
                result.append(f.result(throw_except=throw_except,
                                       internal_storage=self.internal_storage))
            elif not fs and not f._read:
                # Process internally stored futures
                result.append(f.result(throw_except=throw_except,
                                       internal_storage=self.internal_storage))
                f._read = True

        logger.debug(f'ExecutorID {self.executor_id} - Finished getting results')

        if len(result) == 1 and self.last_call != 'map':
            return result[0]

        return result

    def plot(
        self,
        fs: Optional[Union[ResponseFuture, List[ResponseFuture], FuturesList]] = None,
        dst: Optional[str] = None
    ):
        """
        Creates timeline and histogram of the current execution in dst_dir.

        :param fs: list of futures.
        :param dst: destination path to save .png plots.
        """
        ftrs = self.futures if not fs else fs

        if isinstance(ftrs, ResponseFuture):
            ftrs = [ftrs]

        ftrs_to_plot = [f for f in ftrs if (f.success or f.done) and not f.error]

        if not ftrs_to_plot:
            logger.debug(f'ExecutorID {self.executor_id} - No futures ready to plot')
            return

        logging.getLogger('matplotlib').setLevel(logging.WARNING)
        from lithops.plots import create_timeline, create_histogram

        logger.info(f'ExecutorID {self.executor_id} - Creating execution plots')

        create_timeline(ftrs_to_plot, dst)
        create_histogram(ftrs_to_plot, dst)

    def clean(
        self,
        fs: Optional[Union[ResponseFuture, List[ResponseFuture]]] = None,
        cs: Optional[List[CloudObject]] = None,
        clean_cloudobjects: Optional[bool] = True,
        clean_fn: Optional[bool] = False,
        force: Optional[bool] = False
    ):
        """
        Deletes all the temp files from storage. These files include the function,
        the data serialization and the function invocation results. It can also clean
        cloudobjects.

        :param fs: List of futures to clean
        :param cs: List of cloudobjects to clean
        :param clean_cloudobjects: Delete all cloudobjects created with this executor
        :param clean_fn: Delete cached functions in this executor
        :param force: Clean all future objects even if they have not benn completed
        """
        global CLEANER_PROCESS

        def save_data_to_clean(data):
            with tempfile.NamedTemporaryFile(dir=CLEANER_DIR, delete=False) as temp:
                pickle.dump(data, temp)

        try:
            self.internal_storage
        except AttributeError:
            return

        if cs:
            data = {
                'cos_to_clean': list(cs),
                'storage_config': self.internal_storage.get_storage_config()
            }
            save_data_to_clean(data)
            if not fs:
                return

        if clean_fn:
            data = {
                'fn_to_clean': self.executor_id,
                'storage_config': self.internal_storage.get_storage_config()
            }
            save_data_to_clean(data)

        futures = fs or self.futures
        futures = [futures] if type(futures) != list else futures
        present_jobs = {create_job_key(f.executor_id, f.job_id) for f in futures
                        if (f.executor_id.count('-') == 1 and f.done) or force}
        jobs_to_clean = present_jobs - self.cleaned_jobs

        if jobs_to_clean:
            logger.info(f'ExecutorID {self.executor_id} - Cleaning temporary data')
            data = {
                'jobs_to_clean': jobs_to_clean,
                'clean_cloudobjects': clean_cloudobjects,
                'storage_config': self.internal_storage.get_storage_config()
            }
            save_data_to_clean(data)
            self.cleaned_jobs.update(jobs_to_clean)

        spawn_cleaner = not (CLEANER_PROCESS and CLEANER_PROCESS.poll() is None)
        if (jobs_to_clean or cs) and spawn_cleaner:
            cmd = [sys.executable, '-m', 'lithops.scripts.cleaner']
            CLEANER_PROCESS = sp.Popen(cmd, start_new_session=True)

    def job_summary(self, cloud_objects_n: Optional[int] = 0):
        """
        Logs information of a job executed by the calling function executor.
        currently supports: code_engine, ibm_vpc and ibm_cf.

        :param cloud_objects_n: number of cloud object used in COS, declared by user.
        """
        import pandas as pd
        import numpy as np

        def init():
            headers = ['Job_ID', 'Function', 'Invocations', 'Memory(MB)', 'AvgRuntime', 'Cost', 'CloudObjects']
            pd.DataFrame([], columns=headers).to_csv(self.log_path, index=False)

        def append(content):
            """ appends job information to log file."""
            pd.DataFrame(content).to_csv(self.log_path, mode='a', header=False, index=False)

        def append_summary():
            """ add a summary row to the log file"""
            df = pd.read_csv(self.log_path)
            total_average = sum(df.AvgRuntime * df.Invocations) / df.Invocations.sum()
            total_row = pd.DataFrame([['Summary', ' ', df.Invocations.sum(), df['Memory(MB)'].sum(),
                                       round(total_average, 10), df.Cost.sum(), cloud_objects_n]])
            total_row.to_csv(self.log_path, mode='a', header=False, index=False)

        def get_object_num():
            """returns cloud objects used up to this point, using this function executor. """
            df = pd.read_csv(self.log_path)
            return float(df.iloc[-1].iloc[-1])

        # Avoid logging info unless chosen computational backend is supported.
        if hasattr(self.compute_handler.backend, 'calc_cost'):

            if self.log_path:  # retrieve cloud_objects_n from last log file
                cloud_objects_n += get_object_num()
            else:
                self.log_path = os.path.join(constants.LOGS_DIR, datetime.now().strftime("%Y-%m-%d_%H-%M-%S.csv"))
            # override current logfile
            init()

            futures = self.futures
            if type(futures) != list:
                futures = [futures]

            memory = []
            runtimes = []
            curr_job_id = futures[0].job_id
            job_func = futures[0].function_name  # each job is conducted on a single function

            for future in futures:
                if curr_job_id != future.job_id:
                    cost = self.compute_handler.backend.calc_cost(runtimes, memory)
                    append([[curr_job_id, job_func, len(runtimes), sum(memory),
                             np.round(np.average(runtimes), 10), cost, ' ']])

                    # updating next iteration's variables:
                    curr_job_id = future.job_id
                    job_func = future.function_name
                    memory.clear()
                    runtimes.clear()

                memory.append(future.runtime_memory)
                runtimes.append(future.stats['worker_exec_time'])

            # appends last Job-ID
            cost = self.compute_handler.backend.calc_cost(runtimes, memory)
            append([[curr_job_id, job_func, len(runtimes), sum(memory),
                     np.round(np.average(runtimes), 10), cost, ' ']])
            # append summary row to end of the dataframe
            append_summary()

        else:  # calc_cost() doesn't exist for chosen computational backend.
            logger.warning("Could not log job: {} backend isn't supported by this function."
                           .format(self.compute_handler.backend.name))
            return
        logger.info("View log file logs at {}".format(self.log_path))


class LocalhostExecutor(FunctionExecutor):
    """
    Initialize a LocalhostExecutor class.

    :param config: Settings passed in here will override those in config file.
    :param runtime: Runtime name to use.
    :param storage: Name of the storage backend to use.
    :param worker_processes: Worker granularity, number of concurrent/parallel processes in each worker
    :param monitoring: monitoring system.
    :param log_level: log level to use during the execution.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        runtime: Optional[int] = None,
        storage: Optional[str] = None,
        worker_processes: Optional[int] = None,
        monitoring: Optional[str] = None,
        log_level: Optional[str] = False
    ):
        super().__init__(
            backend=LOCALHOST,
            config=config,
            runtime=runtime,
            storage=storage or LOCALHOST,
            log_level=log_level,
            monitoring=monitoring,
            worker_processes=worker_processes
        )


class ServerlessExecutor(FunctionExecutor):
    """
    Initialize a ServerlessExecutor class.

    :param config: Settings passed in here will override those in config file
    :param runtime: Runtime name to use
    :param runtime_memory: memory to use in the runtime
    :param backend: Name of the serverless compute backend to use
    :param storage: Name of the storage backend to use
    :param max_workers: Max number of concurrent workers
    :param worker_processes: Worker granularity, number of concurrent/parallel processes in each worker
    :param monitoring: monitoring system
    :param remote_invoker: Spawn a function that will perform the actual job invocation (True/False)
    :param log_level: log level to use during the execution
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        runtime: Optional[str] = None,
        runtime_memory: Optional[int] = None,
        backend: Optional[str] = None,
        storage: Optional[str] = None,
        max_workers: Optional[int] = None,
        worker_processes: Optional[int] = None,
        monitoring: Optional[str] = None,
        remote_invoker: Optional[bool] = None,
        log_level: Optional[str] = False
    ):
        super().__init__(
            config=config,
            mode='serverless',
            runtime=runtime,
            runtime_memory=runtime_memory,
            backend=backend,
            storage=storage,
            max_workers=max_workers,
            worker_processes=worker_processes,
            monitoring=monitoring,
            log_level=log_level,
            remote_invoker=remote_invoker
        )


class StandaloneExecutor(FunctionExecutor):
    """
    Initialize a StandaloneExecutor class.

    :param config: Settings passed in here will override those in config file
    :param runtime: Runtime name to use
    :param backend: Name of the standalone compute backend to use
    :param storage: Name of the storage backend to use
    :param max_workers: Max number of concurrent workers
    :param worker_processes: Worker granularity, number of concurrent/parallel processes in each worker
    :param monitoring: monitoring system
    :param log_level: log level to use during the execution
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        runtime: Optional[str] = None,
        backend: Optional[str] = None,
        storage: Optional[str] = None,
        max_workers: Optional[int] = None,
        worker_processes: Optional[int] = None,
        monitoring: Optional[str] = None,
        log_level: Optional[str] = False
    ):
        super().__init__(
            config=config,
            mode='standalone',
            runtime=runtime,
            backend=backend,
            storage=storage,
            max_workers=max_workers,
            worker_processes=worker_processes,
            monitoring=monitoring,
            log_level=log_level
        )
