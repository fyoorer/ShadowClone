#
# (C) Copyright IBM Corp. 2022
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
import time
import logging
import hashlib
from azure.storage.queue import QueueServiceClient

from lithops import utils
from lithops.storage.utils import StorageNoSuchKeyError
from lithops.version import __version__
from lithops.constants import COMPUTE_CLI_MSG

from . import config

logger = logging.getLogger(__name__)


class AzureContainerAppBackend:
    """
    A wrap-up around Azure Container Apps backend.
    """

    def __init__(self, ac_config, internal_storage):
        logger.debug("Creating Azure Container Apps client")
        self.name = 'azure_containers'
        self.type = 'faas'
        self.ac_config = ac_config
        self.internal_storage = internal_storage
        self.trigger = ac_config['trigger']
        self.resource_group = ac_config['resource_group']
        self.storage_account_name = ac_config['storage_account_name']
        self.storage_account_key = ac_config['storage_account_key']
        self.location = ac_config['location']
        self.environment = ac_config['environment']

        self.queue_service_url = f'https://{self.storage_account_name}.queue.core.windows.net'
        self.queue_service = QueueServiceClient(account_url=self.queue_service_url,
                                                credential=self.storage_account_key)

        logger.debug(f'Invocation trigger set to: {self.trigger}')

        msg = COMPUTE_CLI_MSG.format('Azure Container Apps')
        logger.info(f"{msg} - Location: {self.location}")

    def _format_containerapp_name(self, runtime_name, runtime_memory, version=__version__):
        """
        Formates the conatiner app name
        """
        ac_name = self.storage_account_name
        name = f'{ac_name}-{runtime_name}-{self.trigger}-{runtime_memory}'
        name_hash = hashlib.sha1(name.encode("utf-8")).hexdigest()[:10]

        return f'lithops-worker-{version.replace(".", "")}-{name_hash}'[:31]

    def _get_default_runtime_image_name(self):
        """
        Generates the default runtime image name
        """
        return utils.get_default_container_name(
            self.name, self.ac_config, 'lithops-azurecontainers-default'
        )

    def deploy_runtime(self, runtime_name, memory, timeout):
        """
        Deploys a new runtime into Azure Function Apps
        from the provided Linux image for consumption plan
        """
        if runtime_name == self._get_default_runtime_image_name():
            self._build_default_runtime(runtime_name)

        logger.info(f"Deploying runtime: {runtime_name} - Memory: {memory} Timeout: {timeout}")
        self._create_app(runtime_name, memory, timeout)
        metadata = self._generate_runtime_meta(runtime_name, memory)

        return metadata

    def _build_default_runtime(self, runtime_name):
        """
        Builds the default runtime
        """
        logger.debug('Building default runtime')
        # Build default runtime using local dokcer
        dockerfile = "Dockefile.default-az-runtime"
        with open(dockerfile, 'w') as f:
            f.write(f"FROM python:{utils.CURRENT_PY_VERSION}-slim-buster\n")
            f.write(config.DEFAULT_DOCKERFILE)
        try:
            self.build_runtime(runtime_name, dockerfile)
        finally:
            os.remove(dockerfile)

    def build_runtime(self, runtime_name, dockerfile, extra_args=[]):
        """
        Builds a new runtime from a Docker file and pushes it to the Docker hub
        """
        logger.info(f'Building runtime {runtime_name} from {dockerfile}')

        docker_path = utils.get_docker_path()

        if dockerfile:
            assert os.path.isfile(dockerfile), f'Cannot locate "{dockerfile}"'
            cmd = f'{docker_path} build -t {runtime_name} -f {dockerfile} . '
        else:
            cmd = f'{docker_path} build -t {runtime_name} . '
        cmd = cmd + ' '.join(extra_args)

        try:
            entry_point = os.path.join(os.path.dirname(__file__), 'entry_point.py')
            utils.create_handler_zip(config.FH_ZIP_LOCATION, entry_point, 'lithopsentry.py')
            utils.run_command(cmd)
        finally:
            os.remove(config.FH_ZIP_LOCATION)

        logger.debug(f'Pushing runtime {runtime_name} to container registry')
        if utils.is_podman(docker_path):
            cmd = f'{docker_path} push {runtime_name} --format docker --remove-signatures'
        else:
            cmd = f'{docker_path} push {runtime_name}'
        utils.run_command(cmd)

        logger.debug(f'Runtime {runtime_name} built successfully')

    def _create_app(self, runtime_name, memory, timeout):
        """
        Create and publish an Azure Container App
        """
        logger.info(f'Creating Azure Container App from runtime {runtime_name}')
        containerapp_name = self._format_containerapp_name(runtime_name, memory)

        if self.trigger == 'pub/sub':
            try:
                logger.debug(f'Creating queue {containerapp_name}')
                self.queue_service.create_queue(containerapp_name)
            except Exception:
                in_queue = self.queue_service.get_queue_client(containerapp_name)
                in_queue.clear_messages()

        ca_temaplate = config.CONTAINERAPP_JSON
        ca_temaplate['name'] = containerapp_name
        ca_temaplate['location'] = self.location
        ca_temaplate['tags']['type'] = 'lithops-runtime'
        ca_temaplate['tags']['lithops_version'] = str(__version__)
        ca_temaplate['tags']['runtime_name'] = runtime_name
        ca_temaplate['tags']['runtime_memory'] = str(memory)

        try:
            runtime_memory, runtime_cpu = config.ALLOWED_MEM[memory]
            ca_temaplate['properties']['template']['containers'][0]['resources']['cpu'] = runtime_cpu
            ca_temaplate['properties']['template']['containers'][0]['resources']['memory'] = runtime_memory
        except Exception:
            raise Exception(f'The memory {memory} is not allowed, you must choose '
                            f'one of thses memory values: {config.ALLOWED_MEM.keys()}')

        ca_temaplate['properties']['template']['containers'][0]['image'] = runtime_name
        ca_temaplate['properties']['template']['containers'][0]['env'][0]['value'] = containerapp_name
        ca_temaplate['properties']['template']['scale']['rules'][0]['azureQueue']['queueName'] = containerapp_name
        ca_temaplate['properties']['template']['scale']['maxReplicas'] = min(self.ac_config['max_workers'], 30)

        cmd = f"az containerapp env show -g {self.resource_group} -n {self.environment} --query id"
        envorinemnt_id = utils.run_command(cmd, return_result=True)
        ca_temaplate['properties']['managedEnvironmentId'] = envorinemnt_id

        cmd = f"az storage account show-connection-string -g {self.resource_group} --name {self.storage_account_name} --query connectionString --out json"
        queueconnection = utils.run_command(cmd, return_result=True)
        ca_temaplate['properties']['configuration']['secrets'][0]['value'] = queueconnection

        if self.ac_config.get('docker_password'):
            ca_temaplate['properties']['configuration']['secrets'][1]['value'] = self.ac_config['docker_password']
            ca_temaplate['properties']['configuration']['registries'][0]['server'] = self.ac_config['docker_server']
            ca_temaplate['properties']['configuration']['registries'][0]['username'] = self.ac_config['docker_user']
        else:
            del ca_temaplate['properties']['configuration']['secrets'][1]
            del ca_temaplate['properties']['configuration']['registries']

        with open(config.CA_JSON_LOCATION, 'w') as f:
            f.write(json.dumps(ca_temaplate))

        cmd = (f'az containerapp create --name {containerapp_name} '
               f'--resource-group {self.resource_group} '
               f'--yaml {config.CA_JSON_LOCATION}')

        try:
            utils.run_command(cmd)
        finally:
            os.remove(config.CA_JSON_LOCATION)

    def delete_runtime(self, runtime_name, memory, version=__version__):
        """
        Deletes a runtime
        """
        logger.info(f'Deleting runtime: {runtime_name} - {memory}MB')
        containerapp_name = self._format_containerapp_name(runtime_name, memory, version)
        cmd = f'az containerapp delete --name {containerapp_name} --resource-group {self.resource_group} -y'
        utils.run_command(cmd)

        try:
            self.queue_service.delete_queue(containerapp_name)
        except Exception:
            pass

    def invoke(self, runtime_name, memory, payload):
        """
        Invoke Container App
        """
        containerapp_name = self._format_containerapp_name(runtime_name, memory)

        if self.trigger == 'pub/sub':
            in_queue = self.queue_service.get_queue_client(containerapp_name)
            msg = in_queue.send_message(utils.dict_to_b64str(payload))
            activation_id = msg.id

            return activation_id

    def get_runtime_key(self, runtime_name, runtime_memory, version=__version__):
        """
        Method that creates and returns the runtime key.
        Runtime keys are used to uniquely identify runtimes within the storage,
        in order to know which runtimes are installed and which not.
        """
        containerapp_name = self._format_containerapp_name(runtime_name, runtime_memory, version)
        runtime_key = os.path.join(self.name, version, containerapp_name)

        return runtime_key

    def clean(self):
        """
        Deletes all Lithops Azure Function Apps runtimes
        """
        logger.debug('Deleting all runtimes')

        runtimes = self.list_runtimes()

        for runtime_name, runtime_memory, version in runtimes:
            self.delete_runtime(runtime_name, runtime_memory, version)

    def _generate_runtime_meta(self, runtime_name, memory):
        """
        Extract metadata from Azure runtime
        """
        logger.info(f"Extracting metadata from: {runtime_name}")
        containerapp_name = self._format_containerapp_name(runtime_name, memory)

        payload = {
            'log_level': logger.getEffectiveLevel(),
            'get_metadata': True,
            'containerapp_name': containerapp_name,
            'storage_config': self.internal_storage.storage.config
        }

        self.invoke(runtime_name, memory=memory, payload=payload)

        logger.debug('Waiting for get-metadata job to finish')
        status_key = containerapp_name + '.meta'

        for i in range(0, 10):
            try:
                time.sleep(15)
                runtime_meta_json = self.internal_storage.get_data(key=status_key)
                runtime_meta = json.loads(runtime_meta_json)
                self.internal_storage.del_data(key=status_key)
                logger.debug("Metadata extracted succesfully")
                return runtime_meta
            except StorageNoSuchKeyError:
                logger.debug(f'Get runtime metadata retry {i+1}')

        raise Exception('Could not get metadata. Review container logs in the Azure Portal')

    def list_runtimes(self, runtime_name='all'):
        """
        List all the Azure Function Apps deployed.
        """
        logger.debug('Listing all deployed runtimes')

        runtimes = []
        response = os.popen('az containerapp list --query "[].{Name:name, Tags:tags}\"').read()
        response = json.loads(response)

        for containerapp in response:
            if containerapp['Tags'] and 'type' in containerapp['Tags'] \
               and containerapp['Tags']['type'] == 'lithops-runtime':
                name = containerapp['Tags']['runtime_name']
                memory = containerapp['Tags']['runtime_memory']
                version = containerapp['Tags']['lithops_version']
                if runtime_name == containerapp['Name'] or runtime_name == 'all':
                    runtimes.append((name, memory, version))

        return runtimes

    def get_runtime_info(self):
        """
        Method that returns all the relevant information about the runtime set
        in config
        """
        if 'runtime' not in self.ac_config or self.ac_config['runtime'] == 'default':
            self.ac_config['runtime'] = self._get_default_runtime_image_name()

        runtime_info = {
            'runtime_name': self.ac_config['runtime'],
            'runtime_memory': self.ac_config['runtime_memory'],
            'runtime_timeout': self.ac_config['runtime_timeout'],
            'max_workers': self.ac_config['max_workers'],
        }

        return runtime_info
