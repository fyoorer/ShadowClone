#
# Copyright Cloudlab URV 2021
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import base64
import copy
import json
import os
import re
import logging
import subprocess
import sys
import time
import boto3

from lithops import utils
from lithops.version import __version__
from lithops.constants import COMPUTE_CLI_MSG
from lithops.storage.utils import StorageNoSuchKeyError

from . import config as batch_config

logger = logging.getLogger(__name__)


class AWSBatchBackend:

    def __init__(self, aws_batch_config, internal_storage):
        """
        Initialize AWS Batch Backend
        """
        logger.debug('Creating AWS Lambda client')

        self.name = 'aws_batch'
        self.type = 'batch'
        self.aws_batch_config = aws_batch_config

        self.user_key = aws_batch_config['access_key_id'][-4:]
        self.package = f'lithops_v{__version__.replace(".", "-")}_{self.user_key}'
        self.region_name = aws_batch_config['region_name']

        self._env_type = self.aws_batch_config['env_type']
        self._queue_name = f'{self.package}_{self._env_type.replace("_", "-")}_queue'
        self._compute_env_name = f'{self.package}_{self._env_type.replace("_", "-")}_env'

        logger.debug('Creating Boto3 AWS Session and Batch Client')
        self.aws_session = boto3.Session(aws_access_key_id=aws_batch_config['access_key_id'],
                                         aws_secret_access_key=aws_batch_config['secret_access_key'],
                                         aws_session_token=aws_batch_config.get('session_token'),
                                         region_name=self.region_name)
        self.batch_client = self.aws_session.client('batch', region_name=self.region_name)

        self.internal_storage = internal_storage

        if 'account_id' in self.aws_batch_config:
            self.account_id = self.aws_batch_config['account_id']
        else:
            sts_client = self.aws_session.client('sts', region_name=self.region_name)
            self.account_id = sts_client.get_caller_identity()["Account"]

        self.ecr_client = self.aws_session.client('ecr', region_name=self.region_name)

        msg = COMPUTE_CLI_MSG.format('AWS Batch')
        logger.info("{} - Region: {}".format(msg, self.region_name))

    def _get_default_runtime_image_name(self):
        python_version = utils.CURRENT_PY_VERSION.replace('.', '')
        revision = 'latest' if 'dev' in __version__ else __version__.replace('.', '')
        return f'batch-default-runtime-v{python_version}:{revision}'

    def _get_full_image_name(self, runtime_name):
        full_image_name = runtime_name if ':' in runtime_name else f'{runtime_name}:latest'
        registry = f'{self.account_id}.dkr.ecr.{self.region_name}.amazonaws.com'
        full_image_name = '/'.join([registry, self.package.replace('-', '.'), full_image_name]).lower()
        repo_name = full_image_name.split('/', 1)[1:].pop().split(':')[0]
        return full_image_name, registry, repo_name

    def _format_jobdef_name(self, runtime_name, runtime_memory, version=__version__):
        fmt_runtime_name = runtime_name.replace('/', '--').replace(':', '--')
        package = self.package.replace(__version__.replace(".", "-"), version.replace(".", "-"))
        return f'{package}--{self._env_type}--{fmt_runtime_name}--{runtime_memory}mb'

    def _unformat_jobdef_name(self, jobdef_name):
        # Default jobdef name is "lithops_v2-7-2_WU5O--FARGATE_SPOT--batch-default-runtime-v39--latest--1024mb"
        prefix, env_type, runtime = jobdef_name.split('--', 2)
        version = prefix.replace('lithops_v', '').split('_')[0].replace('-', '.')
        runtime_name, memory = runtime.rsplit("--", 1)
        return runtime_name.replace('--', ':'), memory.replace('mb', ''), version

    def _build_default_runtime(self, runtime_name):
        # Build default runtime using local docker
        python_version = utils.version_str(sys.version_info)
        dockerfile = "Dockerfile.default-batch-runtime"
        with open(dockerfile, 'w') as f:
            f.write(f"FROM python:{python_version}-slim-buster\n")
            f.write(batch_config.DOCKERFILE_DEFAULT)
        try:
            self.build_runtime(runtime_name, dockerfile)
        finally:
            os.remove(dockerfile)

    def _create_compute_env(self):
        compute_env = self._get_compute_env(self._compute_env_name)

        if compute_env is None:
            logger.debug(f'Creating new Compute Environment {self._compute_env_name}')
            compute_resources_spec = {
                'type': self.aws_batch_config['env_type'],
                'maxvCpus': self.aws_batch_config['env_max_cpus'],
                'subnets': self.aws_batch_config['subnets'],
                'securityGroupIds': self.aws_batch_config['security_groups']
            }

            if self._env_type == 'SPOT':
                compute_resources_spec['allocationStrategy'] = 'SPOT_CAPACITY_OPTIMIZED'

            if self._env_type in {'EC2', 'SPOT'}:
                compute_resources_spec['instanceRole'] = self.aws_batch_config['instance_role']
                compute_resources_spec['minvCpus'] = 0
                compute_resources_spec['instanceTypes'] = ['optimal']

            if 'service_role' in self.aws_batch_config:
                res = self.batch_client.create_compute_environment(
                    computeEnvironmentName=self._compute_env_name,
                    type='MANAGED',
                    computeResources=compute_resources_spec,
                    serviceRole=self.aws_batch_config['service_role']
                )
            else:
                res = self.batch_client.create_compute_environment(
                    computeEnvironmentName=self._compute_env_name,
                    type='MANAGED',
                    computeResources=compute_resources_spec,
                )

            if res['ResponseMetadata']['HTTPStatusCode'] != 200:
                raise Exception(res)

            created = False
            while not created:
                compute_env = self._get_compute_env(self._compute_env_name)
                if compute_env['status'] == 'VALID':
                    created = True
                elif compute_env['status'] == 'CREATING':
                    logger.debug(f'Compute environment is being created... (status: {compute_env["status"]})')
                    time.sleep(3)
                else:
                    logger.error(res)
                    raise Exception(f'Could not create compute environment (status is {compute_env["status"]})')

            logger.debug(f'Compute Environment {self._compute_env_name} successfully created')
        else:
            if compute_env['status'] != 'VALID' or compute_env['state'] != 'ENABLED':
                logger.error(compute_env)
                raise Exception('Compute env status must be VALID and state ENABLED')
            logger.debug(f'Using existing Compute Environment {self._compute_env_name}')

    def _get_compute_env(self, ce_name=None):
        res = self.batch_client.describe_compute_environments()

        if res['ResponseMetadata']['HTTPStatusCode'] != 200:
            raise Exception(res)

        if ce_name is None:
            compute_envs = [ce for ce in res['computeEnvironments'] if
                            self.package in ce['computeEnvironmentName']]
            return compute_envs

        compute_envs = [ce for ce in res['computeEnvironments'] if ce['computeEnvironmentName'] == ce_name]
        if len(compute_envs) == 0:
            return None
        if len(compute_envs) == 1:
            return compute_envs.pop()
        if len(compute_envs) > 1:
            logger.error(compute_envs)
            raise Exception('More than one compute env with the same name')

    def _create_queue(self):
        job_queue = self._get_job_queue(self._queue_name)

        if job_queue is None:
            logger.debug('Creating new Queue {}'.format(self._queue_name))
            res = self.batch_client.create_job_queue(
                jobQueueName=self._queue_name,
                priority=1,
                computeEnvironmentOrder=[
                    {
                        'order': 1,
                        'computeEnvironment': self._compute_env_name
                    },
                ],
            )

            if res['ResponseMetadata']['HTTPStatusCode'] != 200:
                raise Exception(res)

            created = False
            while not created:
                job_queue = self._get_job_queue(self._queue_name)
                if job_queue['status'] == 'VALID':
                    created = True
                elif job_queue['status'] == 'CREATING':
                    logger.debug('Job queue is being created... (status: {})'.format(job_queue['status']))
                    time.sleep(3)
                else:
                    logger.error(res)
                    raise Exception('Could not create job queue (status is {})'.format(job_queue['status']))

            logger.debug('Queue {} successfully created'.format(self._queue_name))
        else:
            if job_queue['status'] != 'VALID' or job_queue['state'] != 'ENABLED':
                logger.error(job_queue)
                raise Exception('Job queue status must be VALID and state ENABLED')
            logger.debug('Using existing Queue {}'.format(self._queue_name))

    def _get_job_queue(self, jq_name=None):
        res = self.batch_client.describe_job_queues()

        if res['ResponseMetadata']['HTTPStatusCode'] != 200:
            raise Exception(res)

        if jq_name is None:
            job_queues = [jq for jq in res['jobQueues']
                          if self.package in jq['jobQueueName']]
            return job_queues

        job_queues = [jq for jq in res['jobQueues'] if jq['jobQueueName'] == jq_name]
        if len(job_queues) == 0:
            return None
        if len(job_queues) == 1:
            return job_queues.pop()
        if len(job_queues) > 1:
            logger.error(job_queues)
            raise Exception('More than one job queue with the same name')

    def _create_job_def(self, runtime_name, runtime_memory):
        job_def_name = self._format_jobdef_name(runtime_name, runtime_memory)
        job_def = self._get_job_def(job_def_name)

        if self._env_type in {'EC2', 'SPOT'}:
            platform_capabilities = ['EC2']
        elif self._env_type in {'FARGATE', 'FARGATE_SPOT'}:
            platform_capabilities = ['FARGATE']
        else:
            raise Exception(f'Unknown env type {self._env_type}')

        if job_def is None:
            logger.debug(f'Creating new Job Definition {job_def_name}')
            image_name, _, _ = self._get_full_image_name(runtime_name)

            container_properties = {
                'image': image_name,
                'executionRoleArn': self.aws_batch_config['execution_role'],
                'resourceRequirements': [
                    {
                        'type': 'VCPU',
                        'value': str(self.aws_batch_config['container_vcpus'])
                    },
                    {
                        'type': 'MEMORY',
                        'value': str(self.aws_batch_config['runtime_memory'])
                    }
                ],
            }

            if self._env_type in {'FARGATE', 'FARGATE_SPOT'}:
                container_properties['networkConfiguration'] = {
                    'assignPublicIp': 'ENABLED' if self.aws_batch_config['assign_public_ip'] else 'DISABLED'
                }

            res = self.batch_client.register_job_definition(
                jobDefinitionName=job_def_name,
                type='container',
                containerProperties=container_properties,
                platformCapabilities=platform_capabilities
            )

            if res['ResponseMetadata']['HTTPStatusCode'] != 200:
                raise Exception(res)
            logger.debug('Job Definition {} successfully created'.format(job_def_name))
        else:
            if job_def['status'] != 'ACTIVE':
                logger.error(job_def)
                raise Exception('Job queue status must be VALID and state ENABLED')
            logger.debug('Using existing Job Definition {}'.format(job_def_name))

    def _get_job_def(self, jd_name=None):
        res = self.batch_client.describe_job_definitions(status='ACTIVE')

        if res['ResponseMetadata']['HTTPStatusCode'] != 200:
            raise Exception(res)

        if jd_name is None:
            job_defs = [jd for jd in res['jobDefinitions']
                        if self.package in jd['jobDefinitionName']]
            return job_defs

        job_defs = [jd for jd in res['jobDefinitions'] if jd['jobDefinitionName'] == jd_name]
        if len(job_defs) == 0:
            return None
        if len(job_defs) == 1:
            return job_defs.pop()
        if len(job_defs) > 1:
            logger.error(job_defs)
            raise Exception('More than one job def with the same name')

    def _generate_runtime_meta(self, runtime_name, runtime_memory):
        logger.info(f"Extracting metadata from: {runtime_name}")

        job_name = '{}_metadata'.format(self._format_jobdef_name(runtime_name, runtime_memory))

        payload = copy.deepcopy(self.internal_storage.storage.config)
        payload['runtime_name'] = runtime_name
        payload['log_level'] = logger.getEffectiveLevel()

        logger.debug(f'Submitting get-metadata job for runtime {runtime_name}')
        res = self.batch_client.submit_job(
            jobName=job_name,
            jobQueue=self._queue_name,
            jobDefinition=self._format_jobdef_name(runtime_name, runtime_memory),
            containerOverrides={
                'environment': [
                    {
                        'name': '__LITHOPS_ACTION',
                        'value': 'get_metadata'
                    },
                    {
                        'name': '__LITHOPS_PAYLOAD',
                        'value': json.dumps(payload)
                    }
                ]
            }
        )

        logger.debug('Waiting for get-metadata job to finish')
        status_key = runtime_name + '.meta'
        retry = 0
        while retry < 10:
            logger.debug('Getting runtime metadata...')
            try:
                runtime_meta_json = self.internal_storage.get_data(key=status_key)
                runtime_meta = json.loads(runtime_meta_json)
                self.internal_storage.del_data(key=status_key)
                return runtime_meta
            except StorageNoSuchKeyError:
                time.sleep(20)
                retry += 1
        raise Exception('Could not get metadata')

    def build_runtime(self, runtime_name, runtime_file, extra_args=[]):
        logger.info(f'Building runtime {runtime_name} from {runtime_file}')

        docker_path = utils.get_docker_path()

        expression = '^([a-zA-Z0-9_-]+)(:[a-zA-Z0-9_-]+)+$'
        result = re.match(expression, runtime_name)

        if not result or result.group() != runtime_name:
            raise Exception(f"Runtime name must satisfy regex {expression}")

        res = self.ecr_client.get_authorization_token()
        if res['ResponseMetadata']['HTTPStatusCode'] != 200:
            raise Exception(f'Could not get ECR auth token: {res}')

        auth_data = res['authorizationData'].pop()
        ecr_token = base64.b64decode(auth_data['authorizationToken']).split(b':')[1]

        full_image_name, registry, repo_name = self._get_full_image_name(runtime_name)

        if runtime_file:
            assert os.path.isfile(runtime_file), f'Cannot locate "{runtime_file}"'
            cmd = f'{docker_path} build -t {full_image_name} -f {runtime_file} . '
        else:
            cmd = f'{docker_path} build -t {full_image_name} . '
        cmd = cmd + ' '.join(extra_args)

        try:
            entry_point = os.path.join(os.path.dirname(__file__), 'entry_point.py')
            utils.create_handler_zip(os.path.join(os.getcwd(), batch_config.RUNTIME_ZIP), entry_point)
            utils.run_command(cmd)
        finally:
            os.remove(batch_config.RUNTIME_ZIP)

        cmd = f'{docker_path} login --username AWS --password-stdin {registry}'
        subprocess.check_output(cmd.split(), input=ecr_token)

        try:
            self.ecr_client.create_repository(repositoryName=repo_name,
                                              imageTagMutability='MUTABLE')
        except self.ecr_client.exceptions.RepositoryAlreadyExistsException as e:
            logger.info('Repository {} already exists'.format(repo_name))

        logger.debug(f'Pushing runtime {full_image_name} to AWS container registry')
        cmd = f'{docker_path} push {full_image_name}'
        utils.run_command(cmd)

        logger.debug(f'Runtime {runtime_name} built successfully')

    def deploy_runtime(self, runtime_name, memory, timeout=900):
        if runtime_name == self._get_default_runtime_image_name():
            self._build_default_runtime(runtime_name)

        logger.info(f"Deploying runtime: {runtime_name} - Memory: {memory} Timeout: {timeout}")
        self._create_compute_env()
        self._create_queue()
        self._create_job_def(runtime_name, memory)

        runtime_meta = self._generate_runtime_meta(runtime_name, memory)
        return runtime_meta

    def delete_runtime(self, runtime_name, runtime_memory, version=__version__):
        jobdef_name = self._format_jobdef_name(runtime_name, runtime_memory, version)
        job_def = self._get_job_def(jobdef_name)

        logger.info('Deleting job definition with ARN {}'.format(job_def['jobDefinitionArn']))
        res = self.batch_client.deregister_job_definition(jobDefinition=job_def['jobDefinitionArn'])
        if res['ResponseMetadata']['HTTPStatusCode'] != 200:
            logger.error(res)
            raise Exception('Could not deregister job definition {}'.format(job_def['jobDefinitionArn']))

    def clean(self):
        # Delete Job Definition
        job_defs = self._get_job_def()
        for job_def in job_defs:
            logger.info('Deregister job definition {}'.format(job_def['jobDefinitionArn']))
            res = self.batch_client.deregister_job_definition(jobDefinition=job_def['jobDefinitionArn'])
            if res['ResponseMetadata']['HTTPStatusCode'] != 200:
                logger.error(res)
                raise Exception('Could not deregister job definition {}'.format(job_def['jobDefinitionArn']))

        # Delete Job Queue
        job_queues = self._get_job_queue()
        for job_queue in job_queues:
            res = self.batch_client.update_job_queue(
                jobQueue=job_queue['jobQueueArn'],
                state='DISABLED'
            )
            if res['ResponseMetadata']['HTTPStatusCode'] != 200:
                logger.error(res)
                raise Exception('Could not disable job queue {}'.format(job_queue['jobQueueArn']))
            while True:
                jq_status = self._get_job_queue(jq_name=job_queue['jobQueueName'])
                if jq_status['status'] == 'VALID':
                    break
                logger.info('Updating job queue {} (status is {})'.format(
                    job_queue['jobQueueName'], jq_status['status']))
                time.sleep(5)
            res = self.batch_client.delete_job_queue(
                jobQueue=job_queue['jobQueueArn']
            )
            if res['ResponseMetadata']['HTTPStatusCode'] != 200:
                logger.error(res)
                raise Exception('Could not delete job queue {}'.format(job_queue['jobQueueArn']))
            while True:
                jq_status = self._get_job_queue(jq_name=job_queue['jobQueueName'])
                if jq_status is None or jq_status['status'] == 'DELETED':
                    break
                logger.info('Deleting job queue {} (status is {})'.format(
                    job_queue['jobQueueName'], jq_status['status']))
                time.sleep(30)
            logger.info('Job queue {} deleted'.format(job_queue['jobQueueName']))

        # Delete Compute Environment
        compute_envs = self._get_compute_env()
        for compute_env in compute_envs:
            res = self.batch_client.update_compute_environment(
                computeEnvironment=compute_env['computeEnvironmentArn'],
                state='DISABLED'
            )
            if res['ResponseMetadata']['HTTPStatusCode'] != 200:
                logger.error(res)
                raise Exception('Could not disable compute environment {}'.format(compute_env['computeEnvironmentArn']))
            while True:
                ce_status = self._get_compute_env(ce_name=compute_env['computeEnvironmentName'])
                if ce_status['status'] == 'VALID':
                    break
                logger.info('Updating compute environment {} (status is {})'.format(
                    ce_status['computeEnvironmentName'], ce_status['status']))
                time.sleep(5)
            res = self.batch_client.delete_compute_environment(
                computeEnvironment=compute_env['computeEnvironmentArn']
            )
            if res['ResponseMetadata']['HTTPStatusCode'] != 200:
                logger.error(res)
                raise Exception('Could not delete compute environment {}'.format(compute_env['computeEnvironmentArn']))
            while True:
                ce_status = self._get_compute_env(ce_name=compute_env['computeEnvironmentName'])
                if ce_status is None or ce_status['status'] == 'DELETED':
                    break
                logger.info('Deleting compute environment {} (status is {})'.format(
                    compute_env['computeEnvironmentName'], ce_status['status']))
                time.sleep(30)
            logger.info('Compute environment {} deleted'.format(compute_env['computeEnvironmentName']))

        # Delete ECR runtime image
        # for job_def in job_defs:
        #     runtime_name, runtime_memory = self._unformat_jobdef_name(jobdef_name=job_def['jobDefinitionName'])
        #     full_image_name, registry, repo_name = self._get_full_image_name(runtime_name)
        #     self.ecr_client.delete_repository(repositoryName=repo_name, force=True)

    def list_runtimes(self, runtime_name='all'):
        runtimes = []

        for job_def in self._get_job_def():
            rt_name, rt_mem, version = self._unformat_jobdef_name(jobdef_name=job_def['jobDefinitionName'])
            if runtime_name != 'all' and runtime_name != rt_name:
                continue
            runtimes.append((rt_name, rt_mem, version))

        return runtimes

    def invoke(self, runtime_name, runtime_memory, payload):
        total_calls = payload['total_calls']
        chunksize = payload['chunksize']
        total_workers = total_calls // chunksize + (total_calls % chunksize > 0)

        job_name = '{}_{}'.format(self._format_jobdef_name(runtime_name, runtime_memory), payload['job_key'])

        if total_workers > 1:
            res = self.batch_client.submit_job(
                jobName=job_name,
                jobQueue=self._queue_name,
                jobDefinition=self._format_jobdef_name(runtime_name, runtime_memory),
                arrayProperties={
                    'size': total_workers
                },
                containerOverrides={
                    'environment': [
                        {
                            'name': '__LITHOPS_ACTION',
                            'value': 'run_job'
                        },
                        {
                            'name': '__LITHOPS_PAYLOAD',
                            'value': json.dumps(payload)
                        }
                    ]
                }
            )
        else:
            res = self.batch_client.submit_job(
                jobName=job_name,
                jobQueue=self._queue_name,
                jobDefinition=self._format_jobdef_name(runtime_name, runtime_memory),
                containerOverrides={
                    'environment': [
                        {
                            'name': '__LITHOPS_ACTION',
                            'value': 'run_job'
                        },
                        {
                            'name': '__LITHOPS_PAYLOAD',
                            'value': json.dumps(payload)
                        }
                    ]
                }
            )

    def get_runtime_key(self, runtime_name, runtime_memory, version=__version__):
        jobdef_name = self._format_jobdef_name(runtime_name, runtime_memory, version)
        runtime_key = os.path.join(self.name, version, self.region_name, jobdef_name)
        return runtime_key

    def get_runtime_info(self):
        """
        Method that returns all the relevant information about the runtime set
        in config
        """
        if 'runtime' not in self.aws_batch_config or self.aws_batch_config['runtime'] == 'default':
            self.aws_batch_config['runtime'] = self._get_default_runtime_image_name()

        runtime_info = {
            'runtime_name': self.aws_batch_config['runtime'],
            'runtime_memory': self.aws_batch_config['runtime_memory'],
            'runtime_timeout': self.aws_batch_config['runtime_timeout'],
            'max_workers': self.aws_batch_config['max_workers'],
        }

        return runtime_info
