#
# (C) Copyright Cloudlab URV 2021
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
import base64
import hashlib
import json
import logging
import copy
import time
import yaml
import urllib3
from kubernetes import client, watch
from kubernetes.config import load_kube_config, load_incluster_config, list_kube_config_contexts
from kubernetes.client.rest import ApiException

from lithops import utils
from lithops.version import __version__
from lithops.constants import COMPUTE_CLI_MSG, JOBS_PREFIX

from . import config


logger = logging.getLogger(__name__)
urllib3.disable_warnings()


class KubernetesBackend:
    """
    A wrap-up around Code Engine backend.
    """

    def __init__(self, k8s_config, internal_storage):
        logger.debug("Creating Kubernetes Job client")
        self.name = 'k8s'
        self.type = 'batch'
        self.k8s_config = k8s_config
        self.internal_storage = internal_storage

        self.kubecfg_path = k8s_config.get('kubecfg_path')
        self.user_agent = k8s_config['user_agent']

        try:
            load_kube_config(config_file=self.kubecfg_path)
            contexts = list_kube_config_contexts(config_file=self.kubecfg_path)
            current_context = contexts[1].get('context')
            self.namespace = current_context.get('namespace', 'default')
            self.cluster = current_context.get('cluster')
            self.k8s_config['namespace'] = self.namespace
            self.k8s_config['cluster'] = self.cluster
            self.is_incluster = False
        except Exception:
            logger.debug('Loading incluster config')
            load_incluster_config()
            self.namespace = self.k8s_config.get('namespace', 'default')
            self.cluster = self.k8s_config.get('cluster', 'default')
            self.is_incluster = True

        logger.debug(f"Set namespace to {self.namespace}")
        logger.debug(f"Set cluster to {self.cluster}")

        self.batch_api = client.BatchV1Api()
        self.core_api = client.CoreV1Api()

        self.jobs = []  # list to store executed jobs (job_keys)

        msg = COMPUTE_CLI_MSG.format('Kubernetes Job')
        logger.info(f"{msg} - Namespace: {self.namespace}")

    def _format_job_name(self, runtime_name, runtime_memory, version=__version__):
        name = f'{runtime_name}-{runtime_memory}-{version}'
        name_hash = hashlib.sha1(name.encode("utf-8")).hexdigest()[:10]

        return f'lithops-worker-{version.replace(".", "")}-{name_hash}'

    def _get_default_runtime_image_name(self):
        """
        Generates the default runtime image name
        """
        return utils.get_default_container_name(
            self.name, self.k8s_config, 'lithops-kubernetes-default'
        )

    def build_runtime(self, docker_image_name, dockerfile, extra_args=[]):
        """
        Builds a new runtime from a Docker file and pushes it to the Docker hub
        """
        logger.info(f'Building runtime {docker_image_name} from {dockerfile}')

        docker_path = utils.get_docker_path()

        if dockerfile:
            assert os.path.isfile(dockerfile), f'Cannot locate "{dockerfile}"'
            cmd = f'{docker_path} build -t {docker_image_name} -f {dockerfile} . '
        else:
            cmd = f'{docker_path} build -t {docker_image_name} . '
        cmd = cmd + ' '.join(extra_args)

        try:
            entry_point = os.path.join(os.path.dirname(__file__), 'entry_point.py')
            utils.create_handler_zip(config.FH_ZIP_LOCATION, entry_point, 'lithopsentry.py')
            utils.run_command(cmd)
        finally:
            os.remove(config.FH_ZIP_LOCATION)

        logger.debug(f'Pushing runtime {docker_image_name} to container registry')
        if utils.is_podman(docker_path):
            cmd = f'{docker_path} push {docker_image_name} --format docker --remove-signatures'
        else:
            cmd = f'{docker_path} push {docker_image_name}'
        utils.run_command(cmd)

        logger.debug('Building done!')

    def _build_default_runtime(self, docker_image_name):
        """
        Builds the default runtime
        """
        # Build default runtime using local dokcer
        dockerfile = "Dockefile.default-k8s-runtime"
        with open(dockerfile, 'w') as f:
            f.write(f"FROM python:{utils.CURRENT_PY_VERSION}-slim-buster\n")
            f.write(config.DOCKERFILE_DEFAULT)
        try:
            self.build_runtime(docker_image_name, dockerfile)
        finally:
            os.remove(dockerfile)

    def _create_container_registry_secret(self):
        """
        Create the container registry secret in the cluster
        (only if credentials are present in config)
        """
        if not all(key in self.k8s_config for key in ["docker_user", "docker_password"]):
            return

        logger.debug('Creating container registry secret')
        docker_server = self.k8s_config['docker_server']
        docker_user = self.k8s_config['docker_user']
        docker_password = self.k8s_config['docker_password']

        cred_payload = {
            "auths": {
                docker_server: {
                    "Username": docker_user,
                    "Password": docker_password
                }
            }
        }

        data = {
            ".dockerconfigjson": base64.b64encode(
                json.dumps(cred_payload).encode()
            ).decode()
        }

        secret = client.V1Secret(
            api_version="v1",
            data=data,
            kind="Secret",
            metadata=dict(name="lithops-regcred", namespace=self.namespace),
            type="kubernetes.io/dockerconfigjson",
        )

        try:
            self.core_api.delete_namespaced_secret("lithops-regcred", self.namespace)
        except ApiException as e:
            pass

        try:
            self.core_api.create_namespaced_secret(self.namespace, secret)
        except ApiException as e:
            if e.status != 409:
                raise e

    def deploy_runtime(self, docker_image_name, memory, timeout):
        """
        Deploys a new runtime
        """
        try:
            default_image_name = self._get_default_runtime_image_name()
        except Exception:
            default_image_name = None
        if docker_image_name == default_image_name:
            self._build_default_runtime(docker_image_name)

        logger.info(f"Deploying runtime: {docker_image_name} - Memory: {memory} Timeout: {timeout}")
        self._create_container_registry_secret()
        runtime_meta = self._generate_runtime_meta(docker_image_name)

        return runtime_meta

    def delete_runtime(self, docker_image_name, memory, version=__version__):
        """
        Deletes a runtime
        """
        pass

    def clean(self, force=True):
        """
        Deletes all jobs
        """
        logger.debug('Cleaning kubernetes Jobs')

        try:
            jobs = self.batch_api.list_namespaced_job(namespace=self.namespace)
            for job in jobs.items:
                if job.metadata.labels['type'] == 'lithops-runtime'\
                   and (job.status.completion_time is not None or force):
                    job_name = job.metadata.name
                    logger.debug(f'Deleting job {job_name}')
                    try:
                        self.batch_api.delete_namespaced_job(
                            name=job_name,
                            namespace=self.namespace,
                            propagation_policy='Background'
                        )
                    except Exception:
                        pass
        except ApiException:
            pass

    def clear(self, job_keys=None):
        """
        Delete only completed jobs
        """
        jobs_to_delete = job_keys or self.jobs

        for job_key in jobs_to_delete:
            job_name = f'lithops-{job_key.lower()}'
            logger.debug(f'Deleting job {job_name}')
            try:
                self.batch_api.delete_namespaced_job(
                    name=job_name,
                    namespace=self.namespace,
                    propagation_policy='Background'
                )
            except Exception:
                pass
            try:
                self.jobs.remove(job_key)
            except ValueError:
                pass

    def list_runtimes(self, docker_image_name='all'):
        """
        List all the runtimes
        return: list of tuples (docker_image_name, memory)
        """
        logger.debug('Listing runtimes')
        logger.debug('Note that k8s job backend does not manage runtimes')
        return []

    def _start_master(self, docker_image_name):

        job_name = 'lithops-master'

        master_pods = self.core_api.list_namespaced_pod(
            namespace=self.namespace,
            label_selector=f"job-name={job_name}"
        )

        if len(master_pods.items) > 0:
            return master_pods.items[0].status.pod_ip

        logger.debug('Starting Lithops master Pod')
        try:
            self.batch_api.delete_namespaced_job(
                name=job_name,
                namespace=self.namespace,
                propagation_policy='Background'
            )
            time.sleep(2)
        except Exception as e:
            pass

        job_res = yaml.safe_load(config.JOB_DEFAULT)
        job_res['metadata']['name'] = job_name
        job_res['metadata']['namespace'] = self.namespace
        container = job_res['spec']['template']['spec']['containers'][0]
        container['image'] = docker_image_name
        container['env'][0]['value'] = 'run_master'

        try:
            self.batch_api.create_namespaced_job(
                namespace=self.namespace,
                body=job_res
            )
        except Exception as e:
            raise e

        w = watch.Watch()
        for event in w.stream(self.core_api.list_namespaced_pod,
                              namespace=self.namespace,
                              label_selector=f"job-name={job_name}"):
            if event['object'].status.phase == "Running":
                return event['object'].status.pod_ip

    def invoke(self, docker_image_name, runtime_memory, job_payload):
        """
        Invoke -- return information about this invocation
        For array jobs only remote_invocator is allowed
        """
        master_ip = self._start_master(docker_image_name)

        workers = job_payload['max_workers']
        executor_id = job_payload['executor_id']
        job_id = job_payload['job_id']

        job_key = job_payload['job_key']
        self.jobs.append(job_key)

        total_calls = job_payload['total_calls']
        chunksize = job_payload['chunksize']
        total_workers = min(workers, total_calls // chunksize + (total_calls % chunksize > 0))

        job_res = yaml.safe_load(config.JOB_DEFAULT)

        activation_id = f'lithops-{job_key.lower()}'

        job_res['metadata']['name'] = activation_id
        job_res['metadata']['namespace'] = self.namespace
        job_res['metadata']['labels']['version'] = 'lithops_v' + __version__

        job_res['spec']['activeDeadlineSeconds'] = self.k8s_config['runtime_timeout']
        job_res['spec']['parallelism'] = total_workers

        container = job_res['spec']['template']['spec']['containers'][0]
        container['image'] = docker_image_name
        if not docker_image_name.endswith(':latest'):
            container['imagePullPolicy'] = 'IfNotPresent'

        container['env'][0]['value'] = 'run_job'
        container['env'][1]['value'] = utils.dict_to_b64str(job_payload)
        container['env'][2]['value'] = master_ip

        container['resources']['requests']['memory'] = f'{runtime_memory}Mi'
        container['resources']['requests']['cpu'] = str(self.k8s_config['runtime_cpu'])
        container['resources']['limits']['memory'] = f'{runtime_memory}Mi'
        container['resources']['limits']['cpu'] = str(self.k8s_config['runtime_cpu'])

        logger.debug('ExecutorID {} | JobID {} - Going '
                     'to run {} activations in {} workers'
                     .format(executor_id, job_id, total_calls, total_workers))

        try:
            self.batch_api.create_namespaced_job(namespace=self.namespace,
                                                 body=job_res)
        except Exception as e:
            raise e

        return activation_id

    def _generate_runtime_meta(self, docker_image_name):
        runtime_name = self._format_job_name(docker_image_name, 128)
        meta_job_name = f'{runtime_name}-meta'

        logger.info(f"Extracting metadata from: {docker_image_name}")

        payload = copy.deepcopy(self.internal_storage.storage.config)
        payload['runtime_name'] = runtime_name
        payload['log_level'] = logger.getEffectiveLevel()

        job_res = yaml.safe_load(config.JOB_DEFAULT)
        job_res['metadata']['name'] = meta_job_name
        job_res['metadata']['namespace'] = self.namespace

        container = job_res['spec']['template']['spec']['containers'][0]
        container['image'] = docker_image_name
        container['env'][0]['value'] = 'get_metadata'
        container['env'][1]['value'] = utils.dict_to_b64str(payload)

        if not all(key in self.k8s_config for key in ["docker_user", "docker_password"]):
            del job_res['spec']['template']['spec']['imagePullSecrets']

        try:
            self.batch_api.delete_namespaced_job(
                namespace=self.namespace,
                name=meta_job_name,
                propagation_policy='Background'
            )
        except Exception as e:
            pass

        try:
            self.batch_api.create_namespaced_job(
                namespace=self.namespace,
                body=job_res
            )
        except Exception as e:
            raise e

        logger.debug("Waiting for runtime metadata")

        done = False
        failed = False

        while not (done or failed):
            try:
                w = watch.Watch()
                for event in w.stream(self.batch_api.list_namespaced_job,
                                      namespace=self.namespace,
                                      field_selector=f"metadata.name={meta_job_name}",
                                      timeout_seconds=10):
                    failed = event['object'].status.failed
                    done = event['object'].status.succeeded
                    logger.debug('...')
                    if done or failed:
                        w.stop()
            except Exception as e:
                pass

        if done:
            logger.debug("Runtime metadata generated successfully")

        try:
            self.batch_api.delete_namespaced_job(
                namespace=self.namespace,
                name=meta_job_name,
                propagation_policy='Background'
            )
        except Exception as e:
            pass

        if failed:
            raise Exception("Unable to extract metadata from the runtime")

        data_key = '/'.join([JOBS_PREFIX, runtime_name + '.meta'])
        json_str = self.internal_storage.get_data(key=data_key)
        runtime_meta = json.loads(json_str.decode("ascii"))
        self.internal_storage.del_data(key=data_key)

        if not runtime_meta or 'preinstalls' not in runtime_meta:
            raise Exception(f'Failed getting runtime metadata: {runtime_meta}')

        return runtime_meta

    def get_runtime_key(self, docker_image_name, runtime_memory, version=__version__):
        """
        Method that creates and returns the runtime key.
        Runtime keys are used to uniquely identify runtimes within the storage,
        in order to know which runtimes are installed and which not.
        """
        jobdef_name = self._format_job_name(docker_image_name, 256, version)
        runtime_key = os.path.join(self.name, version, self.namespace, jobdef_name)

        return runtime_key

    def get_runtime_info(self):
        """
        Method that returns all the relevant information about the runtime set
        in config
        """
        if 'runtime' not in self.k8s_config or self.k8s_config['runtime'] == 'default':
            self.k8s_config['runtime'] = self._get_default_runtime_image_name()

        runtime_info = {
            'runtime_name': self.k8s_config['runtime'],
            'runtime_cpu': self.k8s_config['runtime_cpu'],
            'runtime_memory': self.k8s_config['runtime_memory'],
            'runtime_timeout': self.k8s_config['runtime_timeout'],
            'max_workers': self.k8s_config['max_workers'],
        }

        return runtime_info
