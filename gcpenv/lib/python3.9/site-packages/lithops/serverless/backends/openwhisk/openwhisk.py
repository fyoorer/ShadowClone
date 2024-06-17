#
# (C) Copyright IBM Corp. 2020
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
import logging

from lithops import utils
from lithops.version import __version__
from lithops.libs.openwhisk.client import OpenWhiskClient
from lithops.constants import COMPUTE_CLI_MSG

from . import config

logger = logging.getLogger(__name__)


class OpenWhiskBackend:
    """
    A wrap-up around OpenWhisk Functions backend.
    """

    def __init__(self, ow_config, internal_storage):
        logger.debug("Creating OpenWhisk client")
        self.name = 'openwhisk'
        self.type = 'faas'
        self.ow_config = ow_config
        self.is_lithops_worker = utils.is_lithops_worker()

        self.user_agent = ow_config['user_agent']

        self.endpoint = ow_config['endpoint']
        self.namespace = ow_config['namespace']
        self.api_key = ow_config['api_key']
        self.insecure = ow_config.get('insecure', False)

        logger.debug(f"Set OpenWhisk Endpoint to {self.endpoint}")
        logger.debug(f"Set OpenWhisk Namespace to {self.namespace}")
        logger.debug(f"Set OpenWhisk Insecure to {self.insecure}")

        self.user_key = self.api_key[:5]
        self.package = f'lithops_{self.user_key}'

        self.cf_client = OpenWhiskClient(
            endpoint=self.endpoint,
            namespace=self.namespace,
            api_key=self.api_key,
            insecure=self.insecure,
            user_agent=self.user_agent
        )

        msg = COMPUTE_CLI_MSG.format('OpenWhisk')
        logger.info(f"{msg} - Namespace: {self.namespace}")

    def _format_function_name(self, runtime_name, runtime_memory, version=__version__):
        runtime_name = runtime_name.replace('/', '_').replace(':', '_')
        return f'{runtime_name}_{runtime_memory}MB_{version}'

    def _unformat_function_name(self, action_name):
        runtime_name, memory, version = action_name.rsplit('_', 2)
        image_name = runtime_name.replace('_', '/', 2)
        image_name = image_name.replace('_', ':', -1)
        return version, image_name, int(memory.replace('MB', ''))

    def _get_default_runtime_image_name(self):
        try:
            return config.AVAILABLE_PY_RUNTIMES[utils.CURRENT_PY_VERSION]
        except KeyError:
            raise Exception(f'Unsupported Python version: {utils.CURRENT_PY_VERSION}')

    def build_runtime(self, docker_image_name, dockerfile, extra_args=[]):
        """
        Builds a new runtime from a Docker file and pushes it to the Docker hub
        """
        logger.info(f'Building runtime {docker_image_name} from {dockerfile}')

        docker_path = utils.get_docker_path()

        if dockerfile:
            assert os.path.isfile(dockerfile), f'Cannot locate "{dockerfile}"'
            cmd = f'{docker_path} build --platform=linux/amd64 -t {docker_image_name} -f {dockerfile} . '
        else:
            cmd = f'{docker_path} build --platform=linux/amd64 -t {docker_image_name} . '
        cmd = cmd + ' '.join(extra_args)
        utils.run_command(cmd)

        docker_user = self.ow_config.get("docker_user")
        docker_password = self.ow_config.get("docker_password")
        docker_server = self.ow_config.get("docker_server")

        logger.debug(f'Pushing runtime {docker_image_name} to container registry')

        if docker_user and docker_password:
            cmd = f'{docker_path} login -u {docker_user} --password-stdin {docker_server}'
            utils.run_command(cmd, input=docker_password)

        if utils.is_podman(docker_path):
            cmd = f'{docker_path} push {docker_image_name} --format docker --remove-signatures'
        else:
            cmd = f'{docker_path} push {docker_image_name}'
        utils.run_command(cmd)

        logger.debug('Building done!')

    def deploy_runtime(self, docker_image_name, memory, timeout):
        """
        Deploys a new runtime into Openwhisk namespace from an already built Docker image
        """
        logger.info(f"Deploying runtime: {docker_image_name} - Memory: {memory} Timeout: {timeout}")

        self.cf_client.create_package(self.package)
        action_name = self._format_function_name(docker_image_name, memory)

        entry_point = os.path.join(os.path.dirname(__file__), 'entry_point.py')
        utils.create_handler_zip(config.FH_ZIP_LOCATION, entry_point, '__main__.py')

        try:
            with open(config.FH_ZIP_LOCATION, "rb") as action_zip:
                action_bin = action_zip.read()
            self.cf_client.create_action(
                self.package, action_name, docker_image_name,
                code=action_bin, memory=memory,
                is_binary=True, timeout=timeout * 1000
            )
        finally:
            os.remove(config.FH_ZIP_LOCATION)

        return self._generate_runtime_meta(docker_image_name, memory)

    def delete_runtime(self, docker_image_name, memory, version=__version__):
        """
        Deletes a runtime
        """
        logger.info(f'Deleting runtime: {docker_image_name} - {memory}MB')
        action_name = self._format_function_name(docker_image_name, memory, version)
        self.cf_client.delete_action(self.package, action_name)

    def clean(self):
        """
        Deletes all runtimes from all packages
        """
        packages = self.cf_client.list_packages()
        for pkg in packages:
            if pkg['name'].startswith('lithops') and pkg['name'].endswith(self.user_key):
                actions = self.cf_client.list_actions(pkg['name'])
                while actions:
                    for action in actions:
                        logger.info(f'Deleting function: {action["name"]}')
                        self.cf_client.delete_action(pkg['name'], action['name'])
                    actions = self.cf_client.list_actions(pkg['name'])
                self.cf_client.delete_package(pkg['name'])

    def list_runtimes(self, docker_image_name='all'):
        """
        List all the runtimes deployed in the IBM CF service
        return: list of tuples (docker_image_name, memory)
        """
        runtimes = []

        packages = self.cf_client.list_packages()
        for pkg in packages:
            if pkg['name'] == self.package:
                actions = self.cf_client.list_actions(pkg['name'])
                for action in actions:
                    version, image_name, memory = self._unformat_function_name(action['name'])
                    if docker_image_name == image_name or docker_image_name == 'all':
                        runtimes.append((image_name, memory, version))
        return runtimes

    def invoke(self, docker_image_name, runtime_memory, payload):
        """
        Invoke -- return information about this invocation
        """
        action_name = self._format_function_name(docker_image_name, runtime_memory)

        activation_id = self.cf_client.invoke(self.package, action_name,
                                              payload, self.is_lithops_worker)

        return activation_id

    def get_runtime_key(self, docker_image_name, runtime_memory, version=__version__):
        """
        Method that creates and returns the runtime key.
        Runtime keys are used to uniquely identify runtimes within the storage,
        in order to know which runtimes are installed and which not.
        """
        action_name = self._format_function_name(docker_image_name, runtime_memory, version)
        runtime_key = os.path.join(self.name, version, self.namespace, action_name)

        return runtime_key

    def get_runtime_info(self):
        """
        Method that returns all the relevant information about the runtime set
        in config
        """
        if 'runtime' not in self.ow_config or self.ow_config['runtime'] == 'default':
            self.ow_config['runtime'] = self._get_default_runtime_image_name()

        runtime_info = {
            'runtime_name': self.ow_config['runtime'],
            'runtime_memory': self.ow_config['runtime_memory'],
            'runtime_timeout': self.ow_config['runtime_timeout'],
            'max_workers': self.ow_config['max_workers'],
        }

        return runtime_info

    def _generate_runtime_meta(self, docker_image_name, memory):
        """
        Extract installed Python modules from the docker image
        """
        logger.debug(f"Extracting runtime metadata from: {docker_image_name}")
        action_name = self._format_function_name(docker_image_name, memory)
        payload = {'log_level': logger.getEffectiveLevel(), 'get_metadata': True}
        try:
            retry_invoke = True
            while retry_invoke:
                retry_invoke = False
                runtime_meta = self.cf_client.invoke_with_result(self.package, action_name, payload)
                if 'activationId' in runtime_meta:
                    retry_invoke = True
        except Exception as e:
            raise (f"Unable to extract metadata: {e}")

        if not runtime_meta or 'preinstalls' not in runtime_meta:
            raise Exception(runtime_meta)

        return runtime_meta
