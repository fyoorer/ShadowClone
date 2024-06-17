#
# Copyright 2018 PyWren Team
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

import re
import os
import sys
import uuid
import json
import shutil
import base64
import inspect
import struct
import lithops
import zipfile
import platform
import logging.config
import subprocess as sp

from lithops import constants
from lithops.version import __version__


logger = logging.getLogger(__name__)


def uuid_str():
    return str(uuid.uuid4())


def create_executor_id(lenght=6):
    """ Creates an executor ID. """
    if '__LITHOPS_SESSION_ID' in os.environ:
        session_id = os.environ['__LITHOPS_SESSION_ID']
    else:
        session_id = uuid_str().replace('/', '')[:lenght]
        os.environ['__LITHOPS_SESSION_ID'] = session_id

    if '__LITHOPS_TOTAL_EXECUTORS' in os.environ:
        exec_num = int(os.environ['__LITHOPS_TOTAL_EXECUTORS']) + 1
    else:
        exec_num = 0
    os.environ['__LITHOPS_TOTAL_EXECUTORS'] = str(exec_num)

    return '{}-{}'.format(session_id, exec_num)


def get_executor_id():
    """ retrieves the current executor ID. """
    session_id = os.environ['__LITHOPS_SESSION_ID']
    exec_num = os.environ['__LITHOPS_TOTAL_EXECUTORS']
    return '{}-{}'.format(session_id, exec_num)


def iterchunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def agg_data(data_strs):
    """Auxiliary function that aggregates data of a job to a single
    byte string.
    """
    ranges = []
    pos = 0
    for datum in data_strs:
        datum_len = len(datum)
        ranges.append((pos, pos + datum_len - 1))
        pos += datum_len
    return b"".join(data_strs), ranges


def create_futures_list(futures, executor):
    """creates a new FuturesList an initiates its attrs"""
    fl = FuturesList(futures)
    fl.config = executor.config
    fl.executor = executor

    return fl


class FuturesList(list):

    def _create_executor(self):
        if not self.executor:
            from lithops import FunctionExecutor
            self.executor = FunctionExecutor(config=self.config)

    def _extend_futures(self, fs):
        for fut in self:
            fut._produce_output = False
        if not hasattr(self, 'alt_list'):
            self.alt_list = []
            self.alt_list.extend(self)
        self.alt_list.extend(fs)
        self.clear()
        self.extend(fs)

    def map(self, map_function, sync=False, **kwargs):
        self._create_executor()
        if sync:
            self.executor.wait(self)
        fs = self.executor.map(map_function, self, **kwargs)
        self._extend_futures(fs)
        return self

    def map_reduce(self, map_function, reduce_function, sync=False, **kwargs):
        self._create_executor()
        if sync:
            self.executor.wait(self)
        fs = self.executor.map_reduce(map_function, self, reduce_function, **kwargs)
        self._extend_futures(fs)
        return self

    def wait(self, **kwargs):
        self._create_executor()
        fs_tt = self.alt_list if hasattr(self, 'alt_list') else self
        return self.executor.wait(fs_tt, **kwargs)

    def get_result(self, **kwargs):
        self._create_executor()
        fs_tt = self.alt_list if hasattr(self, 'alt_list') else self
        return self.executor.get_result(fs_tt, **kwargs)

    def __reduce__(self):
        self.executor = None
        return super().__reduce__()


def get_default_backend(mode):
    """ Return lithops execution backend """

    if mode == constants.LOCALHOST:
        return constants.LOCALHOST
    elif mode == constants.SERVERLESS:
        return constants.SERVERLESS_BACKEND_DEFAULT
    elif mode == constants.STANDALONE:
        return constants.STANDALONE_BACKEND_DEFAULT
    elif mode:
        raise Exception("Unknown exeution mode: {}".format(mode))


def get_mode(backend):
    """ Return lithops execution mode """

    if backend is None:
        return constants.MODE_DEFAULT
    elif backend == constants.LOCALHOST:
        return constants.LOCALHOST
    elif backend in constants.SERVERLESS_BACKENDS:
        return constants.SERVERLESS
    elif backend in constants.STANDALONE_BACKENDS:
        return constants.STANDALONE
    elif backend:
        raise Exception("Unknown compute backend: {}".format(backend))


def setup_lithops_logger(log_level=constants.LOGGER_LEVEL,
                         log_format=constants.LOGGER_FORMAT,
                         stream=None, filename=None):
    """Setup logging for lithops."""
    if log_level is None or str(log_level).lower() == 'none':
        return

    if stream is None:
        stream = constants.LOGGER_STREAM

    if filename is None:
        filename = os.devnull

    if type(log_level) is str:
        log_level = logging.getLevelName(log_level.upper())

    config_dict = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'standard': {
                'format': log_format
            },
        },
        'handlers': {
            'console_handler': {
                'level': log_level,
                'formatter': 'standard',
                'class': 'logging.StreamHandler',
                'stream': stream
            },
            'file_handler': {
                'level': log_level,
                'formatter': 'standard',
                'class': 'logging.FileHandler',
                'filename': filename,
                'mode': 'a',
            },
        },
        'loggers': {
            'lithops': {
                'handlers': ['console_handler'],
                'level': log_level,
                'propagate': False
            },
        }
    }

    if filename is not os.devnull:
        config_dict['loggers']['lithops']['handlers'] = ['file_handler']

    logging.config.dictConfig(config_dict)


def create_handler_zip(dst_zip_location, entry_point_files, entry_point_name=None):
    """Create the zip package that is uploaded as a function"""

    logger.debug("Creating function handler zip in {}".format(dst_zip_location))

    def add_folder_to_zip(zip_file, full_dir_path, sub_dir=''):
        for file in os.listdir(full_dir_path):
            full_path = os.path.join(full_dir_path, file)
            if os.path.isfile(full_path):
                zip_file.write(full_path, os.path.join('lithops', sub_dir, file))
            elif os.path.isdir(full_path) and '__pycache__' not in full_path:
                add_folder_to_zip(zip_file, full_path, os.path.join(sub_dir, file))

    try:
        ep_files = entry_point_files if isinstance(entry_point_files, list) else [entry_point_files]
        with zipfile.ZipFile(dst_zip_location, 'w', zipfile.ZIP_DEFLATED) as lithops_zip:
            module_location = os.path.dirname(os.path.abspath(lithops.__file__))
            for ep_file in ep_files:
                ep_name = entry_point_name or os.path.basename(ep_file)
                lithops_zip.write(ep_file, ep_name)
            add_folder_to_zip(lithops_zip, module_location)

    except Exception as e:
        raise Exception(f'Unable to create the {dst_zip_location} package: {e}')


def verify_runtime_name(runtime_name):
    """Check if the runtime name has a correct formating"""
    assert re.match("^[A-Za-z0-9_/.:-]*$", runtime_name),\
        'Runtime name "{}" not valid'.format(runtime_name)


def timeout_handler(error_msg, signum, frame):
    raise TimeoutError(error_msg)


def version_str(version_info):
    """Format the python version information"""
    return "{}.{}".format(version_info[0], version_info[1])


def is_unix_system():
    """Check if the current OS is UNIX"""
    curret_system = platform.system()
    return curret_system != 'Windows'


def is_linux_system():
    """Check if the current OS is LINUX"""
    curret_system = platform.system().lower()
    if curret_system == "linux":
        return True
    else:
        return False


def is_lithops_worker():
    """
    Checks if the current execution is within a lithops worker
    """
    if 'LITHOPS_WORKER' in os.environ:
        return True
    return False


def is_object_processing_function(map_function):
    """
    Checks if a function contains the obj parameter, which means
    the user wants to activate the data processing logic.
    """
    func_sig = inspect.signature(map_function)
    return {'obj'} & set(func_sig.parameters)


def is_notebook():
    try:
        shell = get_ipython().__class__.__name__
        if shell == 'ZMQInteractiveShell':
            return True   # Jupyter notebook or qtconsole
        elif shell == 'TerminalInteractiveShell':
            return False  # Terminal running IPython
        else:
            return False  # Other type (?)
    except NameError:
        return False      # Probably standard Python interpreter


def convert_bools_to_string(extra_env):
    """
    Converts all booleans of a dictionary to a string
    """
    for key in extra_env:
        if type(extra_env[key]) == bool:
            extra_env[key] = str(extra_env[key])

    return extra_env


def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


def sdb_to_dict(item):
    attr = item['Attributes']
    return {c['Name']: c['Value'] for c in attr}


def dict_to_b64str(the_dict):
    bytes_dict = json.dumps(the_dict, default=str).encode()
    b64_dict = base64.b64encode(bytes_dict)
    return b64_dict.decode()


def b64str_to_dict(str_data):
    b64_dict = base64.b64decode(str_data.encode())
    bytes_dict = json.loads(b64_dict)

    return bytes_dict


def bytes_to_b64str(byte_data):
    byte_data_64 = base64.b64encode(byte_data)
    byte_data_64_ascii = byte_data_64.decode('ascii')
    return byte_data_64_ascii


def b64str_to_bytes(str_data):
    str_ascii = str_data.encode('ascii')
    byte_data = base64.b64decode(str_ascii)
    return byte_data


def get_docker_path():
    docker_path = shutil.which('docker')
    podman_path = shutil.which('podman')
    if not docker_path and not podman_path:
        raise Exception('docker/podman command not found. Install docker'
                        '/podman or use an already built runtime')
    return docker_path or podman_path


def get_default_container_name(backend, backend_config, runtime_name):
    """
    Generates the default runtime image name
    Used in serverless/kubernetes-based backends
    """
    python_version = CURRENT_PY_VERSION.replace('.', '')
    img = f'{runtime_name}-v{python_version}:{__version__}'

    docker_server = backend_config['docker_server']

    if 'docker.io' in docker_server:
        # Docker hub container registry
        try:
            docker_user = backend_config['docker_user']
        except Exception:
            raise Exception('You must provide "docker_user" param '
                            f'in config under "{backend}" section')
        return f'docker.io/{docker_user}/{img}'

    elif 'icr.io' in docker_server:
        # IBM container registry
        try:
            docker_namespace = backend_config['docker_namespace']
        except Exception:
            raise Exception('You must provide "docker_namespace" param'
                            f'in config under "{backend}" section')
        return f'{docker_server}/{docker_namespace}/{img}'

    elif 'gcr.io' in docker_server:
        # Google container registry
        try:
            country = backend_config['region'].split('-')[0]
            project_name = backend_config['project_name']
        except Exception:
            raise Exception('You must provide "region" and "project_name" params'
                            'in config under "gcp" section')
        return f'{country}.gcr.io/{project_name}/{img}'

    else:
        return f'{docker_server}/{img}'


def get_docker_username():
    user = None
    docker_path = get_docker_path()

    docker_user_info = sp.check_output(
        f"{docker_path} info", shell=True,
        encoding='UTF-8', stderr=sp.STDOUT
    )
    for line in docker_user_info.splitlines():
        if 'Username' in line:
            _, useranme = line.strip().split(':')
            user = useranme.strip()

    if user is None:
        try:
            cmd = ("docker-credential-desktop list | jq -r 'to_entries[].key' | while "
                   "read; do docker-credential-desktop get <<<$REPLY; break; done")
            docker_user_info = sp.check_output(cmd, shell=True, encoding='UTF-8', stderr=sp.STDOUT)
            docker_data = json.loads(docker_user_info)
            user = docker_data['Username']
        except Exception:
            raise Exception('Unable to get the Docker registry user')

    return user


def split_object_url(obj_url):
    if '://' in obj_url:
        sb, path = obj_url.split('://')
    else:
        sb = None
        path = obj_url

    sb = 'ibm_cos' if sb == 'cos' else sb
    sb = 'aws_s3' if sb == 's3' else sb

    bucket, full_key = path.split('/', 1) if '/' in path else (path, '')

    if full_key.endswith('/'):
        prefix = ''.join(full_key.rsplit('/', 1))
        obj_name = ''
    elif full_key:
        prefix, obj_name = full_key.rsplit('/', 1) if '/' in full_key else ('', full_key)
    else:
        prefix = ''
        obj_name = ''

    return sb, bucket, prefix, obj_name


def split_path(path):

    if (path.startswith("/")):
        path = path[1:]
    ind = path.find("/")
    if (ind > 0):
        bucket_name = path[:ind]
        key = path[ind + 1:]
    else:
        bucket_name = path
        key = None
    return bucket_name, key


def format_data(iterdata, extra_args):
    """
    Converts iteradata to a list with extra_args
    """
    # Format iterdata in a proper way
    if type(iterdata) in [range, set]:
        data = list(iterdata)
    elif type(iterdata) != list and type(iterdata) != FuturesList:
        data = [iterdata]
    else:
        data = iterdata

    if extra_args:
        new_iterdata = []
        for data_i in data:

            if type(data_i) is tuple:
                # multiple args
                if type(extra_args) is not tuple:
                    raise Exception('extra_args must contain args in a tuple')
                new_iterdata.append(data_i + extra_args)

            elif type(data_i) is dict:
                # kwargs
                if type(extra_args) is not dict:
                    raise Exception('extra_args must contain kwargs in a dictionary')
                data_i.update(extra_args)
                new_iterdata.append(data_i)
            else:
                new_iterdata.append((data_i, *extra_args))
        data = new_iterdata

    return data


def verify_args(func, iterdata, extra_args):

    if isinstance(iterdata, FuturesList):
        # this is required for function chaining
        return [{'future': f} for f in iterdata]

    data = format_data(iterdata, extra_args)

    # Verify parameters
    non_verify_args = ['ibm_cos', 'storage', 'id', 'rabbitmq']
    func_sig = inspect.signature(func)

    new_parameters = list()
    for param in func_sig.parameters:
        if param not in non_verify_args:
            new_parameters.append(func_sig.parameters[param])

    new_func_sig = func_sig.replace(parameters=new_parameters)

    new_data = list()
    for elem in data:
        if type(elem) == dict:
            if set(list(new_func_sig.parameters.keys())) <= set(elem):
                new_data.append(elem)
            else:
                raise ValueError("Check the args names in the data. "
                                 "You provided these args: {}, and "
                                 "the args must be: {}"
                                 .format(list(elem.keys()),
                                         list(new_func_sig.parameters.keys())))
        elif type(elem) == tuple:
            new_elem = dict(new_func_sig.bind(*list(elem)).arguments)
            new_data.append(new_elem)
        else:
            # single value (list, string, integer, dict, etc)
            new_elem = dict(new_func_sig.bind(elem).arguments)
            new_data.append(new_elem)

    return new_data


class WrappedStreamingBody:
    """
    Wrap boto3's StreamingBody object to provide enough Python fileobj functionality.

    from https://gist.github.com/debedb/2e5cbeb54e43f031eaf0
    """
    def __init__(self, sb, size):
        # The StreamingBody we're wrapping
        self.sb = sb
        # Initial position
        self.pos = 0
        # Size of the object
        self.size = size

    def tell(self):
        return self.pos

    def read(self, n=None):
        retval = self.sb.read(n)
        if retval == "":
            raise EOFError()
        self.pos += len(retval)
        return retval

    def readline(self):
        try:
            retval = self.sb.readline()
        except struct.error:
            raise EOFError()
        self.pos += len(retval)
        return retval

    def seek(self, offset, whence=0):
        retval = self.pos
        if whence == 2:
            if offset == 0:
                retval = self.size
            else:
                raise Exception("Unsupported")
        elif whence == 1:
            offset = self.pos + offset
            if offset > self.size:
                retval = self.size
            else:
                retval = offset
        # print("In seek(%s, %s): %s, size is %s" % (offset, whence, retval, self.size))

        self.pos = retval
        return retval

    def __str__(self):
        return "WrappedBody"

    def __iter__(self):
        return self

    def __next__(self):
        return self.read(64 * 1024)

    def __getattr__(self, attr):
        if attr == 'tell':
            return self.tell
        elif attr == 'seek':
            return self.seek
        elif attr == 'read':
            return self.read
        elif attr == 'readline':
            return self.readline
        elif attr == '__str__':
            return self.__str__
        elif attr == '__iter__':
            return self.__iter__
        elif attr == '__next__':
            return self.__next__
        else:
            return getattr(self.sb, attr)


class WrappedStreamingBodyPartition(WrappedStreamingBody):
    """
    Wrap boto3's StreamingBody object to provide line integrity of the partitions
    based on the newline character.
    """
    def __init__(self, sb, size, byterange, newline='\n'):
        super().__init__(sb, size)
        # Range of the chunk
        self.range = byterange
        # New line character
        self.newline_char = newline.encode()
        # The first chunk does not contain plusbyte
        self._plusbytes = 0 if not self.range or self.range[0] == 0 else 1
        # To store the first byte of this chunk, which actually is the last byte of previous chunk
        self._first_byte = None
        # Flag that indicates the end of the file
        self._eof = False
        # special logic the first time the stream is read
        self._first_read = True

    def read(self, n=None):
        if self._eof:
            return b''
        # Data always contain one byte from the previous chunk,
        # so l'ets check if it is a \n or not
        if not self._first_byte and self._plusbytes == 1:
            self._first_byte = self.sb.read(self._plusbytes)

        retval = self.sb.read(n)

        self.pos += len(retval)
        first_row_start_pos = 0

        if self._first_read and self._first_byte and \
           self._first_byte != self.newline_char:
            logger.debug('Discarding first partial row')
            # Previous byte is not self.newline_char
            # This means that we have to discard first row because it is cut
            first_row_start_pos = retval.find(self.newline_char) + 1
            self._first_read = False

        last_row_end_pos = self.pos
        # Find end of the line in threshold
        if self.pos > self.size:
            last_byte_pos = retval[self.size - 1:].find(self.newline_char)
            last_row_end_pos = self.size + last_byte_pos
            self._eof = True

        return retval[first_row_start_pos:last_row_end_pos]

    def readline(self):
        if self._eof:
            return b''

        if not self._first_byte and self._plusbytes == 1:
            self._first_byte = self.sb.read(self._plusbytes)
            if self._first_byte != self.newline_char:
                logger.debug('Discarding first partial row')
                self.sb._raw_stream.readline()
        try:
            retval = self.sb._raw_stream.readline()
        except struct.error:
            raise EOFError()
        self.pos += len(retval)

        if self.pos >= self.size:
            self._eof = True

        return retval


def run_command(cmd, return_result=False, input=None):
    kwargs = {}

    if logger.getEffectiveLevel() != logging.DEBUG:
        kwargs['stderr'] = sp.DEVNULL
    if input:
        kwargs['input'] = bytes(input, 'utf-8')

    if return_result:
        result = sp.check_output(cmd.split(), encoding='UTF-8', **kwargs)
        return result.strip().replace('"', '')
    else:
        if logger.getEffectiveLevel() != logging.DEBUG:
            kwargs['stdout'] = sp.DEVNULL
        sp.check_call(cmd.split(), **kwargs)


def is_podman(docker_path):
    try:
        cmd = f'{docker_path} info | grep podman'
        sp.check_output(cmd, shell=True, stderr=sp.STDOUT)
        return True
    except Exception:
        return False


CURRENT_PY_VERSION = version_str(sys.version_info)
