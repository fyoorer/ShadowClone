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

import hashlib
import os
import sys
import logging
import shutil
import json
import lithops
import fc2

from lithops import utils
from lithops.version import __version__
from lithops.constants import COMPUTE_CLI_MSG, TEMP_DIR

from . import config

logger = logging.getLogger(__name__)


class AliyunFunctionComputeBackend:
    """
    A wrap-up around Aliyun Function Compute backend.
    """

    def __init__(self, afc_config, storage_config):
        logger.debug("Creating Aliyun Function Compute client")
        self.name = 'aliyun_fc'
        self.type = 'faas'
        self.afc_config = afc_config
        self.user_agent = afc_config['user_agent']

        self.endpoint = afc_config['public_endpoint']
        self.access_key_id = afc_config['access_key_id']
        self.access_key_secret = afc_config['access_key_secret']
        self.role_arn = afc_config['role_arn']
        self.region = self.endpoint.split('.')[1]

        self.default_service_name = f'{config.SERVICE_NAME}_{self.access_key_id[0:4].lower()}'
        self.service_name = afc_config.get('service', self.default_service_name)

        logger.debug(f"Set Aliyun FC Service to {self.service_name}")
        logger.debug(f"Set Aliyun FC Endpoint to {self.endpoint}")

        self.fc_client = fc2.Client(endpoint=self.endpoint,
                                    accessKeyID=self.access_key_id,
                                    accessKeySecret=self.access_key_secret)

        msg = COMPUTE_CLI_MSG.format('Aliyun Function Compute')
        logger.info(f"{msg} - Region: {self.region}")

    def _format_function_name(self, runtime_name, runtime_memory, version=__version__):
        name = f'{runtime_name}-{runtime_memory}-{version}'
        name_hash = hashlib.sha1(name.encode("utf-8")).hexdigest()[:10]

        return f'lithops-worker-{runtime_name}-v{version.replace(".", "-")}-{name_hash}'

    def _unformat_function_name(self, function_name):
        runtime_name, hash = function_name.rsplit('-', 1)
        runtime_name = runtime_name.replace('lithops-worker-', '')
        runtime_name, version = runtime_name.rsplit('-v', 1)
        version = version.replace('-', '.')
        return version, runtime_name

    def _get_default_runtime_name(self):
        py_version = utils.CURRENT_PY_VERSION.replace('.', '')
        return f'default-runtime-v{py_version}'

    def build_runtime(self, runtime_name, requirements_file, extra_args=[]):
        logger.info(f'Building runtime {runtime_name} from {requirements_file}')

        build_dir = os.path.join(config.BUILD_DIR, runtime_name)

        shutil.rmtree(build_dir, ignore_errors=True)
        os.makedirs(build_dir)

        # Add lithops base modules
        logger.debug("Downloading base modules (via pip install)")
        req_file = os.path.join(build_dir, 'requirements.txt')
        with open(req_file, 'w') as reqf:
            reqf.write(config.REQUIREMENTS_FILE)

        def download_requirements():
            cmd = f'{sys.executable} -m pip install -t {build_dir} -r {req_file} --no-deps'
            utils.run_command(cmd)

        if utils.is_linux_system():
            download_requirements()
        else:
            docker_path = utils.get_docker_path()
            if docker_path:
                # Build the runtime in a docker
                cmd = 'python3 -m pip install -U -t . -r requirements.txt'
                cmd = f'docker run -w /tmp -v {build_dir}:/tmp python:{utils.CURRENT_PY_VERSION}-slim-buster {cmd}'
                utils.run_command(cmd)
            else:
                logger.warning('Aliyun Functions use a Linux environment. Building'
                               'a runtime from a non-Linux environemnt might cause issues')
                download_requirements()

        # Add function handlerd
        current_location = os.path.dirname(os.path.abspath(__file__))
        handler_file = os.path.join(current_location, 'entry_point.py')
        shutil.copy(handler_file, build_dir)

        # Add lithops module
        module_location = os.path.dirname(os.path.abspath(lithops.__file__))
        dst_location = os.path.join(build_dir, 'lithops')

        if os.path.isdir(dst_location):
            logger.warning("Using user specified 'lithops' module from the custom runtime folder. "
                           "Please refrain from including it as it will be automatically installed anyway.")
        else:
            shutil.copytree(module_location, dst_location, ignore=shutil.ignore_patterns('__pycache__'))

        # Create zip file
        os.chdir(build_dir)
        runtime_zip = f'{config.BUILD_DIR}/{runtime_name}.zip'
        if os.path.exists(runtime_zip):
            os.remove(runtime_zip)
        utils.run_command(f'zip -r {runtime_zip} .')
        shutil.rmtree(build_dir, ignore_errors=True)

    def _service_exists(self, service_name):
        """
        Checks if a given service exists
        """
        services = self.fc_client.list_services(prefix=service_name).data['services']
        for serv in services:
            if serv['serviceName'] == service_name:
                return True
        return False

    def _build_default_runtime(self, runtime_name):
        """
        Builds the default runtime
        """
        requirements_file = os.path.join(TEMP_DIR, 'aliyun_default_requirements.txt')
        with open(requirements_file, 'w') as reqf:
            reqf.write(config.REQUIREMENTS_FILE)
        try:
            self.build_runtime(runtime_name, requirements_file)
        finally:
            os.remove(requirements_file)

    def deploy_runtime(self, runtime_name, memory, timeout):
        """
        Deploys a new runtime into Aliyun Function Compute
        with the custom modules for lithops
        """
        logger.info(f"Deploying runtime: {runtime_name} - Memory: {memory} Timeout: {timeout}")

        if not self._service_exists(self.service_name):
            logger.debug(f"creating service {self.service_name}")
            self.fc_client.create_service(self.service_name, role=self.role_arn)

        if runtime_name == self._get_default_runtime_name():
            self._build_default_runtime(runtime_name)

        function_name = self._format_function_name(runtime_name, memory)

        logger.debug(f'Crating function {function_name}')
        functions = self.fc_client.list_functions(self.service_name).data['functions']
        for function in functions:
            if function['functionName'] == function_name:
                logger.debug(f'Function {function_name} already exists. Deleting it')
                self.delete_runtime(runtime_name, memory)

        self.fc_client.create_function(
            serviceName=self.service_name,
            functionName=function_name,
            runtime=config.AVAILABLE_PY_RUNTIMES[utils.CURRENT_PY_VERSION],
            handler='entry_point.main',
            codeZipFile=f'{config.BUILD_DIR}/{runtime_name}.zip',
            memorySize=memory,
            timeout=timeout
        )

        metadata = self._generate_runtime_meta(function_name)

        return metadata

    def delete_runtime(self, runtime_name, memory, version=__version__):
        """
        Deletes a runtime
        """
        logger.info(f'Deleting runtime: {runtime_name} - {memory}MB')
        function_name = self._format_function_name(runtime_name, memory, version)
        self.fc_client.delete_function(self.service_name, function_name)

    def clean(self):
        """"
        Deletes all runtimes from the current service
        """
        logger.debug('Going to delete all deployed runtimes')
        if not self._service_exists(self.service_name):
            return

        functions = self.fc_client.list_functions(self.service_name).data['functions']

        for function in functions:
            function_name = function['functionName']
            if function_name.startswith('lithops-worker'):
                logger.info(f'Going to delete runtime {function_name}')
                self.fc_client.delete_function(self.service_name, function_name)

        self.fc_client.delete_service(self.service_name)

    def list_runtimes(self, runtime_name='all'):
        """
        List all the runtimes deployed in the Aliyun FC service
        return: list of tuples (docker_image_name, memory)
        """
        logger.debug('Listing deployed runtimes')
        runtimes = []

        if not self._service_exists(self.service_name):
            return runtimes

        functions = self.fc_client.list_functions(self.service_name).data['functions']

        for function in functions:
            if function['functionName'].startswith('lithops-worker'):
                memory = function['memorySize']
                version, name = self._unformat_function_name(function['functionName'])
                if runtime_name == name or runtime_name == 'all':
                    runtimes.append((name, memory, version))
        return runtimes

    def invoke(self, runtime_name, memory=None, payload={}):
        """
        Invoke function
        """
        function_name = self._format_function_name(runtime_name, memory)

        try:
            res = self.fc_client.invoke_function(
                serviceName=self.service_name,
                functionName=function_name,
                payload=json.dumps(payload, default=str),
                headers={'x-fc-invocation-type': 'Async'}
            )
        except fc2.fc_exceptions.FcError as e:
            raise (e)

        return res.headers['X-Fc-Request-Id']

    def _generate_runtime_meta(self, function_name):
        """
        Extract installed Python modules from Aliyun runtime
        """
        logger.info(f'Extracting runtime metadata from: {function_name}')
        payload = {'log_level': logger.getEffectiveLevel(), 'get_metadata': True}

        try:
            res = self.fc_client.invoke_function(
                self.service_name, function_name,
                payload=json.dumps(payload, default=str),
                headers={'x-fc-invocation-type': 'Sync'}
            )
            runtime_meta = json.loads(res.data)

        except Exception:
            raise Exception("Unable to extract runtime metadata")

        if not runtime_meta or 'preinstalls' not in runtime_meta:
            raise Exception(runtime_meta)

        logger.debug("Metadata extracted successfully")
        return runtime_meta

    def get_runtime_key(self, runtime_name, runtime_memory, version=__version__):
        """
        Method that creates and returns the runtime key.
        Runtime keys are used to uniquely identify runtimes within the storage,
        in order to know which runtimes are installed and which not.
        """
        function_name = self._format_function_name(runtime_name, runtime_memory, version)
        runtime_key = os.path.join(self.name, version, self.region, self.service_name, function_name)

        return runtime_key

    def get_runtime_info(self):
        """
        Method that returns all the relevant information about the runtime set
        in config
        """
        if utils.CURRENT_PY_VERSION not in config.AVAILABLE_PY_RUNTIMES:
            raise Exception(
                f'Python {utils.CURRENT_PY_VERSION} is not available for Aliyun '
                f'Functions. Please use one of {list(config.AVAILABLE_PY_RUNTIMES.keys())}'
            )

        if 'runtime' not in self.afc_config or self.afc_config['runtime'] == 'default':
            self.afc_config['runtime'] = self._get_default_runtime_name()

        runtime_info = {
            'runtime_name': self.afc_config['runtime'],
            'runtime_memory': self.afc_config['runtime_memory'],
            'runtime_timeout': self.afc_config['runtime_timeout'],
            'max_workers': self.afc_config['max_workers'],
        }

        return runtime_info
