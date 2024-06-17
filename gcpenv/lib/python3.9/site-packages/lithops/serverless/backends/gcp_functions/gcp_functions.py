#
# (C) Copyright Cloudlab URV 2020
# (C) Copyright IBM Corp. 2023
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
import json
import base64
import hashlib
import httplib2
import zipfile
import time
import urllib
import google.auth
import google.oauth2.id_token
from threading import Lock
from google.cloud import pubsub_v1
from google.oauth2 import service_account
from google_auth_httplib2 import AuthorizedHttp
from googleapiclient.discovery import build
from google.auth import jwt

from lithops import utils
from lithops.version import __version__
from lithops.constants import COMPUTE_CLI_MSG, JOBS_PREFIX, TEMP_DIR

invoke_mutex = Lock()

from . import config

logger = logging.getLogger(__name__)


class GCPFunctionsBackend:
    def __init__(self, gcf_config, internal_storage):
        self.name = 'gcp_functions'
        self.type = 'faas'
        self.gcf_config = gcf_config
        self.region = gcf_config['region']
        self.num_retries = gcf_config['retries']
        self.retry_sleep = gcf_config['retry_sleep']
        self.trigger = gcf_config['trigger']
        self.credentials_path = gcf_config.get('credentials_path')

        self.internal_storage = internal_storage

        self._build_api_resource()

        self._api_endpoint = f'https://{self.region}-{self.project_name}.cloudfunctions.net/'
        self._api_token = None

        logger.debug(f'Invocation trigger set to: {self.trigger}')

        msg = COMPUTE_CLI_MSG.format('Google Cloud Functions')
        logger.info(f"{msg} - Region: {self.region} - Project: {self.project_name}")

    def _build_api_resource(self):
        """
        Setup Credentials and resources
        """
        if self.credentials_path and os.path.isfile(self.credentials_path):
            logger.debug(f'Getting GCP credentials from {self.credentials_path}')

            api_cred = service_account.Credentials.from_service_account_file(
                self.credentials_path, scopes=config.SCOPES
            )
            self.project_name = api_cred.project_id
            self.service_account = api_cred.service_account_email

            pubsub_cred = jwt.Credentials.from_service_account_file(
                self.credentials_path,
                audience=config.AUDIENCE
            )
        else:
            logger.debug('Getting GCP credentials from the environment')
            api_cred, self.project_name = google.auth.default(scopes=config.SCOPES)
            self.service_account = api_cred.service_account_email
            pubsub_cred = None

        self._pub_client = pubsub_v1.PublisherClient(credentials=pubsub_cred)

        http = AuthorizedHttp(api_cred, http=httplib2.Http())
        self._api_resource = build(
            'cloudfunctions', config.FUNCTIONS_API_VERSION,
            http=http, cache_discovery=False
        )

        self.gcf_config['project_name'] = self.project_name
        self.gcf_config['service_account'] = self.service_account

    @property
    def _default_location(self):
        return f'projects/{self.project_name}/locations/{self.region}'

    def _format_function_name(self, runtime_name, runtime_memory=None, version=__version__):
        name = f'{runtime_name}-{runtime_memory}-{version}-{self.trigger}-{self.region}'
        name_hash = hashlib.sha1(name.encode("utf-8")).hexdigest()[:10]

        return f'lithops-worker-{runtime_name}-{version.replace(".", "")}-{name_hash}'

    def _format_topic_name(self, function_name):
        return f'{function_name}-{self.region}'

    def _get_default_runtime_name(self):
        py_version = utils.CURRENT_PY_VERSION.replace('.', '')
        return f'default-runtime-v{py_version}'

    def _get_topic_location(self, topic_name):
        return f'projects/{self.project_name}/topics/{topic_name}'

    def _get_function_location(self, function_name):
        return f'{self._default_location}/functions/{function_name}'

    def _get_runtime_bin_location(self, runtime_name):
        function_name = self._format_function_name(runtime_name)
        return config.USER_RUNTIMES_PREFIX + '/' + function_name + '_bin.zip'

    def _encode_payload(self, payload):
        return base64.b64encode(bytes(json.dumps(payload), 'utf-8')).decode('utf-8')

    def _get_token(self, function_name):
        """
        Generates a connection token
        """
        invoke_mutex.acquire()

        if not self._api_token or function_name not in self._function_url:
            logger.debug('Getting authentication token')
            self._function_url = self._api_endpoint + function_name
            if self.credentials_path and os.path.isfile(self.credentials_path):
                os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = self.credentials_path
            auth_req = google.auth.transport.requests.Request()
            self._api_token = google.oauth2.id_token.fetch_id_token(auth_req, self.function_url)

        invoke_mutex.release()

        return self._function_url, self._api_token

    def _list_built_runtimes(self, default_runtimes=True):
        """
        Lists all the built runtimes uploaded by self.build_runtime()
        """
        runtimes = []

        if default_runtimes:
            runtimes.extend(self._get_default_runtime_name())

        user_runtimes_keys = self.internal_storage.storage.list_keys(
            self.internal_storage.bucket, prefix=config.USER_RUNTIMES_PREFIX
        )
        runtimes.extend([runtime for runtime in user_runtimes_keys])
        return runtimes

    def _wait_function_deleted(self, function_location):
        # Wait until function is completely deleted
        while True:
            try:
                response = self._api_resource.projects().locations().functions().get(
                    name=function_location
                ).execute(num_retries=self.num_retries)
                logger.debug(f'Function status is {response["status"]}')
                if response['status'] == 'DELETE_IN_PROGRESS':
                    time.sleep(self.retry_sleep)
                else:
                    raise Exception(f'Unknown status: {response["status"]}')
            except Exception as e:
                logger.debug('Function status is DELETED')
                break

    def _create_function(self, runtime_name, memory, timeout=60):
        """
        Creates all the resources needed by a function
        """
        function_name = self._format_function_name(runtime_name, memory)
        function_location = self._get_function_location(function_name)

        # Create topic
        if self.trigger == 'pub/sub':
            topic_name = self._format_topic_name(function_name)
            topic_location = self._get_topic_location(topic_name)
            logger.debug(f"Creating topic {topic_location}")
            topic_list_response = self._pub_client.list_topics(
                request={'project': f'projects/{self.project_name}'})
            topics = [topic.name for topic in topic_list_response]
            if topic_location in topics:
                logger.debug(f"Topic {topic_location} already exists - Restarting queue")
                self._pub_client.delete_topic(topic=topic_location)
            self._pub_client.create_topic(name=topic_location)

        logger.debug(f"Creating function {function_location}")

        fn_list_response = self._api_resource.projects().locations().functions().list(
            parent=self._default_location
        ).execute(num_retries=self.num_retries)
        if 'functions' in fn_list_response:
            deployed_functions = [fn['name'] for fn in fn_list_response['functions']]
            if function_location in deployed_functions:
                logger.debug(f"Function {function_location} already exists - Deleting function")
                self._api_resource.projects().locations().functions().delete(
                    name=function_location,
                ).execute(num_retries=self.num_retries)
                self._wait_function_deleted(function_location)

        bin_location = self._get_runtime_bin_location(runtime_name)
        cloud_function = {
            'name': function_location,
            'description': 'Lithops Worker for Lithops v' + __version__,
            'entryPoint': 'main',
            'runtime': config.AVAILABLE_PY_RUNTIMES[utils.CURRENT_PY_VERSION],
            'timeout': str(timeout) + 's',
            'availableMemoryMb': memory,
            'serviceAccountEmail': self.service_account,
            'maxInstances': 0,
            'sourceArchiveUrl': f'gs://{self.internal_storage.bucket}/{bin_location}',
            'labels': {
                'type': 'lithops-runtime',
                'lithops_version': __version__.replace('.', '-'),
                'runtime_name': runtime_name
            },
        }

        if self.trigger == 'https':
            cloud_function['httpsTrigger'] = {}

        elif self.trigger == 'pub/sub':
            topic_name = self._format_topic_name(function_name)
            topic_location = self._get_topic_location(topic_name)
            cloud_function['eventTrigger'] = {
                'eventType': 'providers/cloud.pubsub/eventTypes/topic.publish',
                'resource': topic_location,
                'failurePolicy': {}
            }

        response = self._api_resource.projects().locations().functions().create(
            location=self._default_location,
            body=cloud_function
        ).execute(num_retries=self.num_retries)

        # Wait until the function is completely deployed
        logger.info('Waiting for the function to be deployed')
        while True:
            response = self._api_resource.projects().locations().functions().get(
                name=function_location
            ).execute(num_retries=self.num_retries)
            logger.debug(f'Function status is {response["status"]}')
            if response['status'] == 'ACTIVE':
                break
            elif response['status'] == 'OFFLINE':
                raise Exception('Error while deploying Cloud Function')
            elif response['status'] == 'DEPLOY_IN_PROGRESS':
                time.sleep(self.retry_sleep)
            else:
                raise Exception(f"Unknown status {response['status']}")

    def build_runtime(self, runtime_name, requirements_file, extra_args=[]):
        logger.info(f'Building runtime {runtime_name} from {requirements_file}')

        if not requirements_file:
            raise Exception('Please provide a "requirements.txt" file with the necessary modules')

        entry_point = os.path.join(os.path.dirname(__file__), 'entry_point.py')
        runtime_path = config.FH_ZIP_LOCATION.format(runtime_name)
        os.makedirs(os.path.dirname(runtime_path), exist_ok=True)
        utils.create_handler_zip(runtime_path, entry_point, 'main.py')
        with zipfile.ZipFile(runtime_path, 'a') as lithops_zip:
            lithops_zip.write(requirements_file, 'requirements.txt', zipfile.ZIP_DEFLATED)

        logger.debug(f'Runtime {runtime_name} built successfuly')

    def _build_default_runtime(self, runtime_name):
        """
        Builds the default runtime
        """
        requirements_file = os.path.join(TEMP_DIR, 'gcf_default_requirements.txt')
        with open(requirements_file, 'w') as reqf:
            reqf.write(config.REQUIREMENTS_FILE)
        try:
            self.build_runtime(runtime_name, requirements_file)
        finally:
            os.remove(requirements_file)

    def deploy_runtime(self, runtime_name, memory, timeout):
        logger.info(f"Deploying runtime: {runtime_name} - Memory: {memory} - Timeout: {timeout}")

        if runtime_name == self._get_default_runtime_name():
            self._build_default_runtime(runtime_name)

        try:
            runtime_path = config.FH_ZIP_LOCATION.format(runtime_name)
            with open(runtime_path, "rb") as action_zip:
                action_bin = action_zip.read()
            bin_location = self._get_runtime_bin_location(runtime_name)
            self.internal_storage.put_data(bin_location, action_bin)
        finally:
            os.remove(runtime_path)

        self._create_function(runtime_name, memory, timeout)

        # Get runtime metadata
        runtime_meta = self._generate_runtime_meta(runtime_name, memory)

        return runtime_meta

    def delete_runtime(self, runtime_name, runtime_memory, version=__version__):
        function_name = self._format_function_name(runtime_name, runtime_memory, version)
        function_location = self._get_function_location(function_name)
        logger.info(f'Deleting runtime: {runtime_name} - {runtime_memory}MB')

        # Delete function
        self._api_resource.projects().locations().functions().delete(
            name=function_location,
        ).execute(num_retries=self.num_retries)
        logger.debug('Request Ok - Waiting until function is completely deleted')

        self._wait_function_deleted(function_location)

        if self.trigger == 'pub/sub':
            # Delete Pub/Sub topic attached as trigger for the cloud function
            logger.debug('Listing Pub/Sub topics')
            topic_name = self._format_topic_name(function_name)
            topic_location = self._get_topic_location(topic_name)
            topic_list_request = self._pub_client.list_topics(
                request={'project': f'projects/{self.project_name}'}
            )
            topics = [topic.name for topic in topic_list_request]
            if topic_location in topics:
                logger.debug(f'Going to delete topic {topic_name}')
                self._pub_client.delete_topic(topic=topic_location)
                logger.debug(f'Ok - topic {topic_name} deleted')

        # Delete user runtime from storage
        bin_location = self._get_runtime_bin_location(runtime_name)
        user_runtimes = self._list_built_runtimes(default_runtimes=False)
        if bin_location in user_runtimes:
            self.internal_storage.storage.delete_object(
                self.internal_storage.bucket, bin_location)

    def clean(self):
        logger.debug('Going to delete all deployed runtimes')
        runtimes = self.list_runtimes()
        for runtime_name, runtime_memory, version in runtimes:
            self.delete_runtime(runtime_name, runtime_memory, version)

    def list_runtimes(self, runtime_name='all'):
        logger.debug('Listing deployed runtimes')
        response = self._api_resource.projects().locations().functions().list(
            parent=self._default_location
        ).execute(num_retries=self.num_retries)

        runtimes = []
        for func in response.get('functions', []):
            if func['labels'] and 'type' in func['labels'] \
               and func['labels']['type'] == 'lithops-runtime':
                version = func['labels']['lithops_version'].replace('-', '.')
                name = func['labels']['runtime_name']
                memory = func['availableMemoryMb']
                if runtime_name == name or runtime_name == 'all':
                    runtimes.append((name, memory, version))

        return runtimes

    def invoke(self, runtime_name, runtime_memory, payload={}, return_result=False):
        """
        Invoke a function
        """
        exec_id = payload.get('executor_id')
        call_id = payload.get('call_id')
        job_id = payload.get('job_id')

        if exec_id and job_id and call_id:
            logger.debug(f'ExecutorID {exec_id} | JobID {job_id} - Invoking function call {call_id}')
        elif exec_id and job_id:
            logger.debug(f'ExecutorID {exec_id} | JobID {job_id} - Invoking function')
        else:
            logger.debug('Invoking function')

        function_name = self._format_function_name(runtime_name, runtime_memory)

        if self.trigger == 'pub/sub':
            if return_result:
                function_location = self._get_function_location(function_name)
                response = self._api_resource.projects().locations().functions().call(
                    name=function_location,
                    body={'data': json.dumps({'data': self._encode_payload(payload)})}
                ).execute(num_retries=self.num_retries)
                if 'result' in response and response['result'] == 'OK':
                    object_key = '/'.join([JOBS_PREFIX, runtime_name + '.meta'])
                    runtime_meta = json.loads(self.internal_storage.get_data(object_key))
                    self.internal_storage.storage.delete_object(self.internal_storage.bucket, object_key)
                    return runtime_meta
                else:
                    raise Exception(f'Error at retrieving runtime metadata: {response}')
            else:
                topic_location = self._get_topic_location(self._format_topic_name(function_name))
                fut = self._pub_client.publish(
                    topic_location,
                    bytes(json.dumps(payload, default=str).encode('utf-8'))
                )
                invocation_id = fut.result()

        elif self.trigger == 'https':
            function_url, api_token = self._get_token(function_name)
            req = urllib.request.Request(function_url, data=json.dumps(payload, default=str).encode('utf-8'))
            req.add_header("Authorization", f"Bearer {api_token}")
            res = urllib.request.urlopen(req)

            if res.getcode() in (200, 202):
                data = json.loads(res.read())
                if return_result:
                    return data
                return data["activationId"]
            else:
                raise Exception(res.text)

        return invocation_id

    def _generate_runtime_meta(self, runtime_name, runtime_memory):
        """
        Extract metadata from GCP runtime
        """
        logger.debug(f'Extracting runtime metadata from: {runtime_name}')

        payload = {
            'get_metadata': {
                'runtime_name': runtime_name,
                'storage_config': self.internal_storage.storage.config
            },
            'trigger': self.trigger
        }

        try:
            runtime_meta = self.invoke(runtime_name, runtime_memory, payload, return_result=True)
        except Exception as e:
            raise Exception(f"Unable to extract metadata from the runtime: {e}")

        if not runtime_meta or 'preinstalls' not in runtime_meta:
            raise Exception(f'Failed getting runtime metadata: {runtime_meta}')

        logger.debug(f'Ok -- Extraced modules from {runtime_name}')

        runtime_meta = self.invoke(runtime_name, runtime_memory, payload, True)

        return runtime_meta

    def get_runtime_key(self, runtime_name, runtime_memory, version=__version__):
        function_name = self._format_function_name(runtime_name, runtime_memory, version)
        runtime_key = os.path.join(self.name, version, self.project_name, self.region, function_name)
        logger.debug(f'Runtime key: {runtime_key}')

        return runtime_key

    def get_runtime_info(self):
        """
        Method that returns all the relevant information about the runtime set
        in config
        """
        if utils.CURRENT_PY_VERSION not in config.AVAILABLE_PY_RUNTIMES:
            raise Exception(
                f'Python {utils.CURRENT_PY_VERSION} is not available for Google Cloud '
                f'Functions. Please use one of {list(config.AVAILABLE_PY_RUNTIMES.keys())}'
            )

        if 'runtime' not in self.gcf_config or self.gcf_config['runtime'] == 'default':
            self.gcf_config['runtime'] = self._get_default_runtime_name()

        runtime_info = {
            'runtime_name': self.gcf_config['runtime'],
            'runtime_memory': self.gcf_config['runtime_memory'],
            'runtime_timeout': self.gcf_config['runtime_timeout'],
            'max_workers': self.gcf_config['max_workers'],
        }

        return runtime_info
