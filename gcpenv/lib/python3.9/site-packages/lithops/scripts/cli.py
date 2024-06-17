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
import click
import logging
import shutil
import shlex
import subprocess as sp
from itertools import cycle
from concurrent.futures import ThreadPoolExecutor

import lithops
from lithops import Storage
from lithops.version import __version__
from lithops.tests.tests_main import print_test_functions, print_test_groups, run_tests
from lithops.utils import get_mode, setup_lithops_logger, verify_runtime_name, sizeof_fmt
from lithops.config import default_config, extract_storage_config, \
    extract_serverless_config, extract_standalone_config, \
    extract_localhost_config, load_yaml_config
from lithops.constants import CACHE_DIR, LITHOPS_TEMP_DIR, RUNTIMES_PREFIX, \
    JOBS_PREFIX, LOCALHOST, SERVERLESS, STANDALONE, LOGS_DIR, FN_LOG_FILE
from lithops.storage import InternalStorage
from lithops.serverless import ServerlessHandler
from lithops.storage.utils import clean_bucket
from lithops.standalone.standalone import StandaloneHandler
from lithops.localhost.localhost import LocalhostHandler


logger = logging.getLogger(__name__)


def set_config_ow(backend, storage=None, runtime_name=None):
    config_ow = {'lithops': {}}

    if storage:
        config_ow['lithops']['storage'] = storage

    if backend:
        config_ow['lithops']['backend'] = backend
        config_ow['lithops']['mode'] = get_mode(backend)

    if runtime_name:
        config_ow['backend'] = {}
        config_ow['backend']['runtime'] = runtime_name

    return config_ow


@click.group('lithops_cli')
@click.version_option()
def lithops_cli():
    pass


@lithops_cli.command('clean')
@click.option('--config', '-c', default=None, help='path to yaml config file', type=click.Path(exists=True))
@click.option('--backend', '-b', default=None, help='compute backend')
@click.option('--storage', '-s', default=None, help='storage backend')
@click.option('--debug', '-d', is_flag=True, help='debug mode')
@click.option('--all', '-a', is_flag=True, help='delete all, including master VM in case of standalone')
def clean(config, backend, storage, debug, all):
    if config:
        config = load_yaml_config(config)

    log_level = logging.INFO if not debug else logging.DEBUG
    setup_lithops_logger(log_level)
    logger.info('Cleaning all Lithops information')

    config_ow = set_config_ow(backend, storage)
    config = default_config(config, config_ow)
    storage_config = extract_storage_config(config)
    internal_storage = InternalStorage(storage_config)

    mode = config['lithops']['mode']
    backend = config['lithops']['backend']

    if mode == LOCALHOST:
        compute_config = extract_localhost_config(config)
        compute_handler = LocalhostHandler(compute_config)
    elif mode == SERVERLESS:
        compute_config = extract_serverless_config(config)
        compute_handler = ServerlessHandler(compute_config, internal_storage)
    elif mode == STANDALONE:
        compute_config = extract_standalone_config(config)
        compute_handler = StandaloneHandler(compute_config)

    compute_handler.clean(all=all)

    # Clean object storage temp dirs
    storage = internal_storage.storage
    runtimes_path = RUNTIMES_PREFIX if all else RUNTIMES_PREFIX + '/' + backend
    jobs_path = JOBS_PREFIX
    clean_bucket(storage, storage_config['bucket'], runtimes_path, sleep=1)
    clean_bucket(storage, storage_config['bucket'], jobs_path, sleep=1)

    # Clean localhost executor temp dirs
    shutil.rmtree(LITHOPS_TEMP_DIR, ignore_errors=True)
    # Clean local lithops cache
    shutil.rmtree(CACHE_DIR, ignore_errors=True)

    logger.info('All Lithops data cleaned')


@lithops_cli.command('verify')
@click.option('--config', '-c', default=None, help='Path to yaml config file', type=click.Path(exists=True))
@click.option('--backend', '-b', default=None, help='Compute backend')
@click.option('--storage', '-s', default=None, help='Storage backend')
@click.option('--debug', '-d', is_flag=True, help='Debug mode')
@click.option('--test', '-t', default='all', help='Run a specific tester. To avoid running similarly named tests '
                                                  'you may prefix the tester with its test class, '
                                                  'e.g. TestClass.test_name. '
                                                  'Type "-t help" for the complete tests list')
@click.option('--groups', '-g', default=None, help='Run all testers belonging to a specific group.'
                                                   ' type "-g help" for groups list')
@click.option('--fail_fast', '-f', is_flag=True, help='Stops test run upon first occurrence of a failed test')
@click.option('--keep_datasets', '-k', is_flag=True, help='keeps datasets in storage after the test run. '
                                                          'Meant to serve some use-cases in github workflow.')
def verify(test, config, backend, groups, storage, debug, fail_fast, keep_datasets):
    if config:
        config = load_yaml_config(config)

    log_level = logging.INFO if not debug else logging.DEBUG
    setup_lithops_logger(log_level)

    if groups and test == 'all':  # if user specified a group(s) avoid running all tests.
        test = ''

    if test == 'help':
        print_test_functions()
    elif groups == 'help':
        print_test_groups()

    else:
        run_tests(test, config, groups, backend, storage, fail_fast, keep_datasets)


@lithops_cli.command('test')
@click.option('--config', '-c', default=None, help='path to yaml config file', type=click.Path(exists=True))
@click.option('--backend', '-b', default=None, help='compute backend')
@click.option('--storage', '-s', default=None, help='storage backend')
@click.option('--debug', '-d', is_flag=True, help='debug mode')
def test_function(config, backend, storage, debug):
    if config:
        config = load_yaml_config(config)

    log_level = logging.INFO if not debug else logging.DEBUG
    setup_lithops_logger(log_level)

    try:
        import getpass
        username = getpass.getuser()
    except Exception:
        username = 'World'

    def hello(name):
        return 'Hello {}!'.format(name)

    fexec = lithops.FunctionExecutor(config=config, backend=backend, storage=storage)
    fexec.call_async(hello, username)
    result = fexec.get_result()
    print()
    if result == 'Hello {}!'.format(username):
        print(result, 'Lithops is working as expected :)')
    else:
        print(result, 'Something went wrong :(')
    print()


@lithops_cli.command('attach')
@click.option('--config', '-c', default=None, help='path to yaml config file', type=click.Path(exists=True))
@click.option('--backend', '-b', default=None, help='compute backend')
@click.option("--start", is_flag=True, default=False, help="Start the master VM if needed.")
@click.option('--debug', '-d', is_flag=True, help='debug mode')
def attach(config, backend, start, debug):
    """Create or attach to a SSH session on Lithops master VM"""
    if config:
        config = load_yaml_config(config)

    log_level = logging.INFO if not debug else logging.DEBUG
    setup_lithops_logger(log_level)

    config_ow = set_config_ow(backend)
    config = default_config(config, config_ow)

    if config['lithops']['mode'] != STANDALONE:
        raise Exception('lithops attach method is only available for standalone backends')

    compute_config = extract_standalone_config(config)
    compute_handler = StandaloneHandler(compute_config)
    compute_handler.init()

    if start:
        compute_handler.backend.master.start()

    master_ip = compute_handler.backend.master.get_public_ip()
    user = compute_handler.backend.master.ssh_credentials['username']
    key_file = compute_handler.backend.master.ssh_credentials['key_filename'] or '~/.ssh/id_rsa'
    key_file = os.path.abspath(os.path.expanduser(key_file))

    if not os.path.exists(key_file):
        raise Exception(f'Private key file {key_file} does not exists')

    print(f'Got master VM public IP address: {master_ip}')
    print(f'Loading ssh private key from: {key_file}')
    print('Creating SSH Connection to lithops master VM')
    cmd = ('ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" '
           f'-i {key_file} {user}@{master_ip}')

    compute_handler.backend.master.wait_ready()

    sp.run(shlex.split(cmd))


# /---------------------------------------------------------------------------/
#
# lithops storage
#
# /---------------------------------------------------------------------------/

@click.group('storage')
@click.pass_context
def storage(ctx):
    pass


@storage.command('put')
@click.argument('filename', type=click.Path(exists=True))
@click.argument('bucket')
@click.option('--key', '-k', default=None, help='object key')
@click.option('--backend', '-b', default=None, help='storage backend')
@click.option('--debug', '-d', is_flag=True, help='debug mode')
@click.option('--config', '-c', default=None, help='path to yaml config file', type=click.Path(exists=True))
def upload_file(filename, bucket, key, backend, debug, config):
    if config:
        config = load_yaml_config(config)

    log_level = logging.INFO if not debug else logging.DEBUG
    setup_lithops_logger(log_level)
    storage = Storage(config=config, backend=backend)

    def upload_file():
        logger.info(f'Uploading file {filename} to {storage.backend}://{bucket}/{key or filename}')
        if storage.upload_file(filename, bucket, key):
            file_size = os.path.getsize(filename)
            logger.info(f'Upload File {filename} - Size: {sizeof_fmt(file_size)} - Ok')
        else:
            logger.error(f'Upload File {filename} - Error')

    with ThreadPoolExecutor() as ex:
        future = ex.submit(upload_file)
        cy = cycle(r"-\|/")
        while not future.done():
            print("Uploading file " + next(cy), end="\r")
            time.sleep(0.1)
        future.result()


@storage.command('get')
@click.argument('bucket')
@click.argument('key')
@click.option('--out', '-o', default=None, help='output filename')
@click.option('--backend', '-b', default=None, help='storage backend')
@click.option('--debug', '-d', is_flag=True, help='debug mode')
@click.option('--config', '-c', default=None, help='path to yaml config file', type=click.Path(exists=True))
def download_file(bucket, key, out, backend, debug, config):
    if config:
        config = load_yaml_config(config)

    log_level = logging.INFO if not debug else logging.DEBUG
    setup_lithops_logger(log_level)
    storage = Storage(config=config, backend=backend)

    def download_file():
        logger.info(f'Downloading file {storage.backend}://{bucket}/{key} to {out or key}')
        if storage.download_file(bucket, key, out):
            file_size = os.path.getsize(out or key)
            logger.info(f'Download File {key} - Size: {sizeof_fmt(file_size)} - Ok')
        else:
            logger.error(f'Download File {key} - Error')

    with ThreadPoolExecutor() as ex:
        future = ex.submit(download_file)
        cy = cycle(r"-\|/")
        while not future.done():
            print("Downloading file " + next(cy), end="\r")
            time.sleep(0.1)
        future.result()


@storage.command('delete')
@click.argument('bucket')
@click.argument('key', required=False)
@click.option('--prefix', '-p', default=None, help='key prefix')
@click.option('--backend', '-b', default=None, help='storage backend')
@click.option('--debug', '-d', is_flag=True, help='debug mode')
@click.option('--config', '-c', default=None, help='path to yaml config file', type=click.Path(exists=True))
def delete_object(bucket, key, prefix, backend, debug, config):
    if config:
        config = load_yaml_config(config)
    log_level = logging.INFO if not debug else logging.DEBUG
    setup_lithops_logger(log_level)
    storage = Storage(config=config, backend=backend)

    if key:
        logger.info('Deleting object "{}" from bucket "{}"'.format(key, bucket))
        storage.delete_object(bucket, key)
        logger.info('Object deleted successfully')
    elif prefix:
        objs = storage.list_keys(bucket, prefix)
        logger.info('Deleting {} objects with prefix "{}" from bucket "{}"'.format(len(objs), prefix, bucket))
        storage.delete_objects(bucket, objs)
        logger.info('Object deleted successfully')


@storage.command('list')
@click.argument('bucket')
@click.option('--prefix', '-p', default=None, help='key prefix')
@click.option('--backend', '-b', default=None, help='storage backend')
@click.option('--debug', '-d', is_flag=True, help='debug mode')
@click.option('--config', '-c', default=None, help='path to yaml config file', type=click.Path(exists=True))
def list_bucket(prefix, bucket, backend, debug, config):
    if config:
        config = load_yaml_config(config)
    log_level = logging.INFO if not debug else logging.DEBUG
    setup_lithops_logger(log_level)
    storage = Storage(config=config, backend=backend)
    logger.info('Listing objects in bucket {}'.format(bucket))
    objects = storage.list_objects(bucket, prefix=prefix)

    if objects:
        width = max([len(obj['Key']) for obj in objects])

        print('\n{:{width}} \t {} \t\t {:>9}'.format('Key', 'Last modified', 'Size', width=width))
        print('-' * width, '\t', '-' * 20, '\t', '-' * 9)
        for obj in objects:
            key = obj['Key']
            date = obj['LastModified'].strftime("%b %d %Y %H:%M:%S")
            size = sizeof_fmt(obj['Size'])
            print('{:{width}} \t {} \t {:>9}'.format(key, date, size, width=width))
        print()
        print('Total objects: {}'.format(len(objects)))
    else:
        width = 10
        print('\n{:{width}} \t {} \t\t {:>9}'.format('Key', 'Last modified', 'Size', width=width))
        print('-' * width, '\t', '-' * 20, '\t', '-' * 9)
        print('\nThe bucket is empty')


# /---------------------------------------------------------------------------/
#
# lithops logs
#
# /---------------------------------------------------------------------------/

@click.group('logs')
@click.pass_context
def logs(ctx):
    pass


@logs.command('poll')
def poll():
    logging.basicConfig(level=logging.DEBUG)

    def follow(file):
        line = ''
        while True:
            if not os.path.isfile(FN_LOG_FILE):
                break
            tmp = file.readline()
            if tmp:
                line += tmp
                if line.endswith("\n"):
                    yield line
                    line = ''
            else:
                time.sleep(1)

    while True:
        if os.path.isfile(FN_LOG_FILE):
            for line in follow(open(FN_LOG_FILE, 'r')):
                print(line, end='')
        else:
            time.sleep(1)


@logs.command('get')
@click.argument('job_key')
def get_logs(job_key):
    log_file = os.path.join(LOGS_DIR, job_key + '.log')

    if not os.path.isfile(log_file):
        print('The execution id: {} does not exists in logs'.format(job_key))
        return

    with open(log_file, 'r') as content_file:
        print(content_file.read())


# /---------------------------------------------------------------------------/
#
# lithops runtime
#
# /---------------------------------------------------------------------------/

@click.group('runtime')
@click.pass_context
def runtime(ctx):
    pass


@runtime.command('build', context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
@click.argument('name', required=False)
@click.option('--file', '-f', default=None, help='file needed to build the runtime')
@click.option('--config', '-c', default=None, help='path to yaml config file', type=click.Path(exists=True))
@click.option('--backend', '-b', default=None, help='compute backend')
@click.option('--debug', '-d', is_flag=True, default=True, help='debug mode')
@click.pass_context
def build(ctx, name, file, config, backend, debug):
    """ build a serverless runtime. """
    log_level = logging.INFO if not debug else logging.DEBUG
    setup_lithops_logger(log_level)

    verify_runtime_name(name)

    if config:
        config = load_yaml_config(config)

    config_ow = set_config_ow(backend, runtime_name=name)
    config = default_config(config, config_ow, load_storage_config=False)

    if config['lithops']['mode'] != SERVERLESS:
        raise Exception('"lithops build" command is only available for serverless backends')

    compute_config = extract_serverless_config(config)
    compute_handler = ServerlessHandler(compute_config, None)
    runtime_info = compute_handler.get_runtime_info()
    runtime_name = runtime_info['runtime_name']
    compute_handler.build_runtime(runtime_name, file, ctx.args)

    logger.info('Runtime built')


@runtime.command('deploy')
@click.argument('name', required=True)
@click.option('--config', '-c', default=None, help='path to yaml config file', type=click.Path(exists=True))
@click.option('--backend', '-b', default=None, help='compute backend')
@click.option('--storage', '-s', default=None, help='storage backend')
@click.option('--memory', default=None, help='memory used by the runtime', type=int)
@click.option('--timeout', default=None, help='runtime timeout', type=int)
@click.option('--debug', '-d', is_flag=True, default=True, help='debug mode')
def deploy(name, storage, backend, memory, timeout, config, debug):
    """ deploy a serverless runtime """
    log_level = logging.INFO if not debug else logging.DEBUG
    setup_lithops_logger(log_level)

    verify_runtime_name(name)

    if config:
        config = load_yaml_config(config)

    config_ow = set_config_ow(backend, storage, runtime_name=name)
    config = default_config(config, config_ow)

    if config['lithops']['mode'] != SERVERLESS:
        raise Exception('"lithops runtime deploy" command is only available for serverless backends')

    storage_config = extract_storage_config(config)
    internal_storage = InternalStorage(storage_config)
    compute_config = extract_serverless_config(config)
    compute_handler = ServerlessHandler(compute_config, internal_storage)

    runtime_info = compute_handler.get_runtime_info()
    runtime_name = runtime_info['runtime_name']
    runtime_memory = memory or runtime_info['runtime_memory']
    runtime_timeout = timeout or runtime_info['runtime_timeout']

    runtime_key = compute_handler.get_runtime_key(runtime_name, runtime_memory, __version__)
    runtime_meta = compute_handler.deploy_runtime(runtime_name, runtime_memory, runtime_timeout)
    runtime_meta['runtime_timeout'] = runtime_timeout
    internal_storage.put_runtime_meta(runtime_key, runtime_meta)

    logger.info('Runtime deployed')

@runtime.command('list')
@click.option('--config', '-c', default=None, help='path to yaml config file', type=click.Path(exists=True))
@click.option('--backend', '-b', default=None, help='compute backend')
@click.option('--storage', '-s', default=None, help='storage backend')
@click.option('--debug', '-d', is_flag=True, help='debug mode')
def list_runtimes(config, backend, storage, debug):
    """ list all deployed serverless runtime. """
    log_level = logging.INFO if not debug else logging.DEBUG
    setup_lithops_logger(log_level)

    if config:
        config = load_yaml_config(config)

    config_ow = set_config_ow(backend)
    config = default_config(config, config_ow, load_storage_config=False)

    if config['lithops']['mode'] != SERVERLESS:
        raise Exception('"lithops runtime list" command is only available for serverless backends')

    compute_config = extract_serverless_config(config)
    compute_handler = ServerlessHandler(compute_config, None)
    runtimes = compute_handler.list_runtimes()

    if runtimes:
        width = max([len(runtime[0]) for runtime in runtimes])

        print('\n{:{width}} \t {} \t {}'.format('Runtime Name', 'Memory Size', 'Lithops Version', width=width))
        print('-' * width, '\t', '-' * 13, '\t', '-' * 17)
        for runtime in runtimes:
            name = runtime[0]
            mem = runtime[1]
            ver = runtime[2] if len(runtime) == 3 else 'NaN'
            print('{:{width}} \t {} MB \t {}'.format(name, mem, ver, width=width))
        print()
        print('Total runtimes: {}'.format(len(runtimes)))
    else:
        width = 14
        print('\n{:{width}} \t {} \t {}'.format('Runtime Name', 'Memory Size', 'Lithops Version', width=width))
        print('-' * width, '\t', '-' * 13, '\t', '-' * 17)
        print('\nNo runtimes deployed')


@runtime.command('update')
@click.argument('name', required=True)
@click.option('--config', '-c', default=None, help='path to yaml config file', type=click.Path(exists=True))
@click.option('--backend', '-b', default=None, help='compute backend')
@click.option('--storage', '-s', default=None, help='storage backend')
@click.option('--debug', '-d', is_flag=True, help='debug mode')
def update(name, config, backend, storage, debug):
    """ Update a serverless runtime """
    log_level = logging.INFO if not debug else logging.DEBUG
    setup_lithops_logger(log_level)

    verify_runtime_name(name)

    if config:
        config = load_yaml_config(config)

    config_ow = set_config_ow(backend, storage, runtime_name=name)
    config = default_config(config, config_ow)

    if config['lithops']['mode'] != SERVERLESS:
        raise Exception('"lithops runtime update" command is only available for serverless backends')

    storage_config = extract_storage_config(config)
    internal_storage = InternalStorage(storage_config)
    compute_config = extract_serverless_config(config)
    compute_handler = ServerlessHandler(compute_config, internal_storage)

    runtime_info = compute_handler.get_runtime_info()
    runtime_name = runtime_info['runtime_name']
    runtime_timeout = runtime_info['runtime_timeout']

    logger.info(f'Updating runtime: {runtime_name}')

    runtimes = compute_handler.list_runtimes(runtime_name)

    for runtime in runtimes:
        if runtime[2] == __version__:
            runtime_key = compute_handler.get_runtime_key(runtime[0], runtime[1], runtime[2])
            runtime_meta = compute_handler.deploy_runtime(runtime[0], runtime[1], runtime_timeout)
            internal_storage.put_runtime_meta(runtime_key, runtime_meta)

    logger.info('Runtime updated')

@runtime.command('delete')
@click.argument('name', required=True)
@click.option('--config', '-c', default=None, help='path to yaml config file', type=click.Path(exists=True))
@click.option('--memory', '-m', default=None, help='runtime memory')
@click.option('--version', '-v', default=None, help='lithops version')
@click.option('--backend', '-b', default=None, help='compute backend')
@click.option('--storage', '-s', default=None, help='storage backend')
@click.option('--debug', '-d', is_flag=True, help='debug mode')
def delete(name, config, memory, version, backend, storage, debug):
    """ delete a serverless runtime """
    log_level = logging.INFO if not debug else logging.DEBUG
    setup_lithops_logger(log_level)

    verify_runtime_name(name)

    if config:
        config = load_yaml_config(config)

    config_ow = set_config_ow(backend, storage, runtime_name=name)
    config = default_config(config, config_ow)

    if config['lithops']['mode'] != SERVERLESS:
        raise Exception('"lithops runtime delete" command is only available for serverless backends')

    storage_config = extract_storage_config(config)
    internal_storage = InternalStorage(storage_config)
    compute_config = extract_serverless_config(config)
    compute_handler = ServerlessHandler(compute_config, internal_storage)

    runtime_info = compute_handler.get_runtime_info()
    runtime_name = runtime_info['runtime_name']

    runtimes = compute_handler.list_runtimes(runtime_name)
    for runtime in runtimes:
        to_delete = True
        if memory is not None and runtime[1] != int(memory):
            to_delete = False
        if version is not None and runtime[2] != version:
            to_delete = False
        if to_delete:
            compute_handler.delete_runtime(runtime[0], runtime[1], runtime[2])
            runtime_key = compute_handler.get_runtime_key(runtime[0], runtime[1], runtime[2])
            internal_storage.delete_runtime_meta(runtime_key)

    logger.info('Runtime deleted')

lithops_cli.add_command(runtime)
lithops_cli.add_command(logs)
lithops_cli.add_command(storage)

if __name__ == '__main__':
    lithops_cli()
