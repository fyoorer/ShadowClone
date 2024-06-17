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
import json
import urllib
import yaml
import hashlib
import logging
import httplib2
import google.auth
import google.oauth2.id_token
from threading import Lock
from google.oauth2 import service_account
from google_auth_httplib2 import AuthorizedHttp
from googleapiclient.discovery import build

from lithops import utils
from lithops.constants import COMPUTE_CLI_MSG
from lithops.version import __version__

invoke_mutex = Lock()

from . import config

logger = logging.getLogger(__name__)


class GCPCloudRunBackend:

    def __init__(self, cloudrun_config, internal_storage):
        self.name = 'gcp_cloudrun'
        self.type = 'faas'
        self.cr_config = cloudrun_config
        self.region = cloudrun_config['region']
        self.trigger = cloudrun_config['trigger']
        self.credentials_path = cloudrun_config.get('credentials_path')

        self._build_api_resource()

        self._service_url = None
        self._id_token = None

        msg = COMPUTE_CLI_MSG.format('Google Cloud Run')
        logger.info(f"{msg} - Region: {self.region} - Project: {self.project_name}")

    def _format_service_name(self, runtime_name, runtime_memory, version=__version__):
        """
        Formats service name string from runtime name and memory
        """
        name = f'{runtime_name}-{runtime_memory}-{version}-{self.trigger}-{self.region}'
        name_hash = hashlib.sha1(name.encode("utf-8")).hexdigest()[:10]

        return f'lithops-worker-{version.replace(".", "")}-{name_hash}'

    def _get_default_runtime_image_name(self):
        """
        Generates the default runtime image name
        """
        return utils.get_default_container_name(
            self.name, self.cr_config, 'lithops-cloudrun-default'
        )

    def _format_image_name(self, runtime_name):
        """
        Formats GCR image name from runtime name
        """
        if 'gcr.io' not in runtime_name:
            country = self.region.split('-')[0]
            return f'{country}.gcr.io/{self.project_name}/{runtime_name}'
        else:
            return runtime_name

    def _build_api_resource(self):
        """
        Instantiate and authorize admin discovery API session
        """
        if self.credentials_path and os.path.isfile(self.credentials_path):
            logger.debug(f'Getting GCP credentials from {self.credentials_path}')
            cred = service_account.Credentials.from_service_account_file(self.credentials_path, scopes=config.SCOPES)
            self.project_name = cred.project_id
            self.service_account = cred.service_account_email
        else:
            logger.debug('Getting GCP credentials from the environment')
            cred, self.project_name = google.auth.default(scopes=config.SCOPES)
            self.service_account = cred.service_account_email

        http = AuthorizedHttp(cred, http=httplib2.Http())
        self._api_resource = build(
            'run', config.CLOUDRUN_API_VERSION,
            http=http, cache_discovery=False,
            client_options={
                'api_endpoint': f'https://{self.region}-run.googleapis.com'
            }
        )

        self.cr_config['project_name'] = self.project_name
        self.cr_config['service_account'] = self.service_account

    def _get_url_and_token(self, service_name):
        """
        Generates a connection token
        """
        invoke_mutex.acquire()
        request_token = False

        if not self._service_url or service_name not in self._service_url:
            logger.debug('Getting service endpoint')
            res = self._api_resource.namespaces().services().get(
                name=f'namespaces/{self.project_name}/services/{service_name}'
            ).execute()
            self._service_url = res['status']['url']
            request_token = True
            logger.debug(f'Service endpoint url is {self._service_url}')

        if not self._id_token or request_token:
            logger.debug('Getting authentication token')
            if self.credentials_path and os.path.isfile(self.credentials_path):
                os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = self.credentials_path
            auth_req = google.auth.transport.requests.Request()
            self._id_token = google.oauth2.id_token.fetch_id_token(auth_req, self._service_url)
        invoke_mutex.release()

        return self._service_url, self._id_token

    def _build_default_runtime(self, runtime_name):
        """
        Builds the default runtime
        """
        logger.debug(f'Building default {runtime_name} runtime')
        # Build default runtime using local dokcer
        dockerfile = "Dockefile.default-kn-runtime"
        with open(dockerfile, 'w') as f:
            f.write(f"FROM python:{utils.CURRENT_PY_VERSION}-slim-buster\n")
            f.write(config.DEFAULT_DOCKERFILE)
        try:
            self.build_runtime(runtime_name, dockerfile)
        finally:
            os.remove(dockerfile)

    def _generate_runtime_meta(self, runtime_name, runtime_memory):
        """
        Extract installed Python modules from docker image
        """
        logger.info(f"Extracting metadata from: {runtime_name}")

        try:
            runtime_meta = self.invoke(
                runtime_name, runtime_memory,
                {'service_route': '/metadata'},
                return_result=True
            )
        except Exception as e:
            raise Exception(f"Unable to extract metadata from the runtime: {e}")

        if not runtime_meta or 'preinstalls' not in runtime_meta:
            raise Exception(f'Failed getting runtime metadata: {runtime_meta}')

        logger.debug(f'Ok -- Extraced modules from {runtime_name}')
        return runtime_meta

    def invoke(self, runtime_name, runtime_memory, payload, return_result=False):
        """
        Invoke a function as a POST request to the service
        """
        exec_id = payload.get('executor_id')
        call_id = payload.get('call_id')
        job_id = payload.get('job_id')
        route = payload.get("service_route", '/')

        img_name = self._format_image_name(runtime_name)
        service_name = self._format_service_name(img_name, runtime_memory)
        service_url, id_token = self._get_url_and_token(service_name)

        if exec_id and job_id and call_id:
            logger.debug(f'ExecutorID {exec_id} | JobID {job_id} - Invoking function call {call_id}')
        elif exec_id and job_id:
            logger.debug(f'ExecutorID {exec_id} | JobID {job_id} - Invoking function')
        else:
            logger.debug('Invoking function')

        req = urllib.request.Request(service_url + route, data=json.dumps(payload, default=str).encode('utf-8'))
        req.add_header("Authorization", f"Bearer {id_token}")
        res = urllib.request.urlopen(req)

        if res.getcode() in (200, 202):
            data = json.loads(res.read())
            if return_result:
                return data
            return data["activationId"]
        else:
            raise Exception(res.text)

    def build_runtime(self, runtime_name, dockerfile, extra_args=[]):
        logger.info(f'Building runtime {runtime_name} from {dockerfile}')

        image_name = self._format_image_name(runtime_name)

        docker_path = utils.get_docker_path()

        if dockerfile:
            assert os.path.isfile(dockerfile), f'Cannot locate "{dockerfile}"'
            cmd = f'{docker_path} build -t {image_name} -f {dockerfile} . '
        else:
            cmd = f'{docker_path} build -t {image_name} . '
        cmd = cmd + ' '.join(extra_args)

        try:
            entry_point = os.path.join(os.path.dirname(__file__), 'entry_point.py')
            utils.create_handler_zip(config.FH_ZIP_LOCATION, entry_point, 'lithopsproxy.py')
            utils.run_command(cmd)
        finally:
            os.remove(config.FH_ZIP_LOCATION)

        logger.debug('Authorizing Docker client with GCR permissions')
        country = self.region.split('-')[0]
        cmd = f'cat {self.credentials_path} | {docker_path} login {country}.gcr.io -u _json_key --password-stdin'
        if logger.getEffectiveLevel() != logging.DEBUG:
            cmd = cmd + f" >{os.devnull} 2>&1"
        res = os.system(cmd)
        if res != 0:
            raise Exception('There was an error authorizing Docker for push to GCR')

        logger.debug(f'Pushing runtime {image_name} to GCP Container Registry')
        if utils.is_podman(docker_path):
            cmd = f'{docker_path} push {image_name} --format docker --remove-signatures'
        else:
            cmd = f'{docker_path} push {image_name}'
        utils.run_command(cmd)

    def _create_service(self, runtime_name, runtime_memory, timeout):
        """
        Creates a service in knative based on the docker_image_name and the memory provided
        """
        logger.debug("Creating Lithops runtime service in Google Cloud Run")

        img_name = self._format_image_name(runtime_name)
        service_name = self._format_service_name(img_name, runtime_memory)

        svc_res = yaml.safe_load(config.service_res)
        svc_res['metadata']['name'] = service_name
        svc_res['metadata']['namespace'] = self.project_name

        logger.debug(f"Service name: {service_name}")
        logger.debug(f"Namespace: {self.project_name}")

        svc_res['spec']['template']['spec']['timeoutSeconds'] = timeout
        svc_res['spec']['template']['spec']['containerConcurrency'] = 1
        svc_res['spec']['template']['spec']['serviceAccountName'] = self.service_account
        svc_res['spec']['template']['metadata']['labels']['lithops-version'] = __version__.replace('.', '-')
        svc_res['spec']['template']['metadata']['annotations']['autoscaling.knative.dev/minScale'] = str(self.cr_config['min_workers'])
        svc_res['spec']['template']['metadata']['annotations']['autoscaling.knative.dev/maxScale'] = str(self.cr_config['max_workers'])

        container = svc_res['spec']['template']['spec']['containers'][0]
        container['image'] = img_name
        container['env'][0] = {'name': 'CONCURRENCY', 'value': '1'}
        container['env'][1] = {'name': 'TIMEOUT', 'value': str(timeout)}
        container['resources']['limits']['memory'] = f'{runtime_memory}Mi'
        container['resources']['limits']['cpu'] = str(self.cr_config['runtime_cpu'])
        container['resources']['requests']['memory'] = f'{runtime_memory}Mi'
        container['resources']['requests']['cpu'] = str(self.cr_config['runtime_cpu'])

        logger.debug(f"Creating service: {service_name}")
        res = self._api_resource.namespaces().services().create(
            parent=f'namespaces/{self.project_name}', body=svc_res
        ).execute()
        logger.debug(f'Ok -- service created {service_name}')

        # Wait until service is up
        ready = False
        retry = 15
        logger.debug(f'Waiting {service_name} service to become ready')
        while not ready:
            res = self._api_resource.namespaces().services().get(
                name=f'namespaces/{self.project_name}/services/{service_name}'
            ).execute()

            ready = all(cond['status'] == 'True' for cond in res['status']['conditions'])

            if not ready:
                logger.debug('...')
                time.sleep(10)
                retry -= 1
                if retry == 0:
                    raise Exception(f'Maximum retries reached: {res}')
            else:
                self._service_url = res['status']['url']

        logger.debug(f'Ok -- service is up at {self._service_url}')

    def deploy_runtime(self, runtime_name, memory, timeout):
        if runtime_name == self._get_default_runtime_image_name():
            self._build_default_runtime(runtime_name)

        logger.info(f"Deploying runtime: {runtime_name} - Memory: {memory} Timeout: {timeout}")
        self._create_service(runtime_name, memory, timeout)
        runtime_meta = self._generate_runtime_meta(runtime_name, memory)
        return runtime_meta

    def delete_runtime(self, runtime_name, runtime_memory, version=__version__):
        logger.info(f'Deleting runtime: {runtime_name} - {runtime_memory}MB')
        img_name = self._format_image_name(runtime_name)
        service_name = self._format_service_name(img_name, runtime_memory, version)
        self._delete_service(service_name)

    def _delete_service(self, service_name):
        logger.debug(f'Deleting service {service_name}')
        try:
            self._api_resource.namespaces().services().delete(
                name=f'namespaces/{self.project_name}/services/{service_name}'
            ).execute()
            # Wait until the service is completely deleted
            while True:
                try:
                    self._api_resource.namespaces().services().get(
                        name=f'namespaces/{self.project_name}/services/{service_name}'
                    ).execute()
                    time.sleep(1)
                except Exception:
                    break
            logger.debug(f'Ok -- service deleted {service_name}')
        except Exception:
            logger.debug(f'Error -- unable to delete service {service_name}')

    def clean(self):
        logger.debug('Going to delete all deployed runtimes')

        res = self._api_resource.namespaces().services().list(
            parent=f'namespaces/{self.project_name}',
        ).execute()

        if 'items' not in res:
            return

        for item in res['items']:
            labels = item['spec']['template']['metadata']['labels']
            if labels and 'type' in labels and labels['type'] == 'lithops-runtime':
                container = item['spec']['template']['spec']['containers'][0]
                memory = container['resources']['limits']['memory'].replace('Mi', '')
                runtime_name = container['image']
                logger.info(f'Deleting runtime: {runtime_name} - {memory}MB')
                self._delete_service(item['metadata']['name'])

    def list_runtimes(self, runtime_name='all'):
        logger.debug('Listing runtimes')

        res = self._api_resource.namespaces().services().list(
            parent=f'namespaces/{self.project_name}',
        ).execute()

        if 'items' not in res:
            return []

        runtimes = []
        for item in res['items']:
            labels = item['spec']['template']['metadata']['labels']
            if labels and 'type' in labels and labels['type'] == 'lithops-runtime':
                version = labels['lithops-version'].replace('-', '.')
                container = item['spec']['template']['spec']['containers'][0]
                memory = container['resources']['limits']['memory'].replace('Mi', '')
                if runtime_name in container['image'] or runtime_name == 'all':
                    runtimes.append((container['image'], memory, version))

        return runtimes

    def get_runtime_key(self, runtime_name, memory, version=__version__):
        img_name = self._format_image_name(runtime_name)
        service_name = self._format_service_name(img_name, memory, version)
        runtime_key = os.path.join(self.name, version, self.project_name, self.region, service_name)
        logger.debug(f'Runtime key: {runtime_key}')

        return runtime_key

    def get_runtime_info(self):
        """
        Method that returns all the relevant information about the runtime set
        in config
        """
        if 'runtime' not in self.cr_config or self.cr_config['runtime'] == 'default':
            self.cr_config['runtime'] = self._get_default_runtime_image_name()

        runtime_info = {
            'runtime_name': self.cr_config['runtime'],
            'runtime_cpu': self.cr_config['runtime_cpu'],
            'runtime_memory': self.cr_config['runtime_memory'],
            'runtime_timeout': self.cr_config['runtime_timeout'],
            'max_workers': self.cr_config['max_workers'],
        }

        return runtime_info
