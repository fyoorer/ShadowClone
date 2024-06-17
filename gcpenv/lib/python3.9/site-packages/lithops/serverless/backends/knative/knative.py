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
import ssl
import json
import time
import yaml
import base64
import hashlib
import urllib3
import logging
import requests
import http.client
from urllib.parse import urlparse
from kubernetes import client, watch
from kubernetes.config import load_kube_config, load_incluster_config, list_kube_config_contexts
from kubernetes.client.rest import ApiException

from lithops import utils
from lithops.version import __version__
from lithops.config import load_yaml_config, dump_yaml_config
from lithops.constants import CACHE_DIR
from lithops.constants import COMPUTE_CLI_MSG

from . import config

urllib3.disable_warnings()

logger = logging.getLogger(__name__)


class KnativeServingBackend:
    """
    A wrap-up around Knative Serving APIs.
    """

    def __init__(self, knative_config, internal_storage):
        self.name = 'knative'
        self.type = 'faas'
        self.kn_config = knative_config
        self.ingress_endpoint = self.kn_config.get('ingress_endpoint')
        self.kubecfg_path = self.kn_config.get('kubecfg_path')
        self.networking_layer = self.kn_config.get('networking_layer')

        # k8s config can be incluster, in ~/.kube/config or generate kube-config.yaml file and
        # set env variable KUBECONFIG=<path-to-kube-confg>
        try:
            load_kube_config(config_file=self.kubecfg_path)
            contexts = list_kube_config_contexts(config_file=self.kubecfg_path)
            current_context = contexts[1].get('context')
            self.namespace = current_context.get('namespace', 'default')
            self.cluster = current_context.get('cluster')
            self.kn_config['namespace'] = self.namespace
            self.kn_config['cluster'] = self.cluster
            self.is_incluster = False
        except Exception:
            logger.debug('Loading incluster config')
            load_incluster_config()
            self.namespace = self.kn_config.get('namespace', 'default')
            self.cluster = self.kn_config.get('cluster', 'default')
            self.is_incluster = True

        logger.debug(f"Set namespace to {self.namespace}")
        logger.debug(f"Set cluster to {self.cluster}")

        self.custom_api = client.CustomObjectsApi()
        self.core_api = client.CoreV1Api()

        if self.ingress_endpoint is None:
            if self.networking_layer == 'istio':
                namespace = 'istio-system'
                service = 'istio-ingressgateway'
            else:
                namespace = 'kourier-system'
                service = 'kourier'

            try:
                ip = None
                ingress = self.core_api.read_namespaced_service(service, namespace)
                http_port = list(filter(lambda port: port.port == 80, ingress.spec.ports))[0].node_port
                https_port = list(filter(lambda port: port.port == 443, ingress.spec.ports))[0].node_port
                if ingress.status.load_balancer.ingress is not None:
                    # get loadbalancer ip
                    ip = ingress.status.load_balancer.ingress[0].ip
                else:
                    # for a single node deployment
                    node = self.core_api.list_node()
                    if not ip:
                        for addr in node.items[0].status.addresses:
                            if addr.type == "ExternalIP":
                                ip = addr.address
                    if not ip:
                        for addr in node.items[0].status.addresses:
                            if addr.type == "InternalIP":
                                ip = addr.address
                    if not ip:
                        ip = node.items[0].status.addresses[0].address
                if ip and http_port:
                    self.ingress_endpoint = f'http://{ip}:{http_port}'
                    self.kn_config['ingress_endpoint'] = self.ingress_endpoint
                    logger.debug(f"Ingress endpoint set to {self.ingress_endpoint}")
            except Exception as e:
                pass

        if 'service_host_suffix' not in self.kn_config:
            self.serice_host_filename = os.path.join(CACHE_DIR, 'knative', self.cluster, 'service_host')
            self.service_host_suffix = None
            if os.path.exists(self.serice_host_filename):
                serice_host_data = load_yaml_config(self.serice_host_filename)
                self.service_host_suffix = serice_host_data['service_host_suffix']
                self.kn_config['service_host_suffix'] = self.service_host_suffix
        else:
            self.service_host_suffix = self.kn_config['service_host_suffix']
        if self.service_host_suffix is not None:
            logger.debug(f'Loaded service host suffix: {self.service_host_suffix}')

        logger.info(f'{COMPUTE_CLI_MSG.format("Knative")} - Cluster: {self.cluster}')

    def _format_service_name(self, runtime_name, runtime_memory, version=__version__):
        name = f'{runtime_name}-{runtime_memory}-{version}'
        name_hash = hashlib.sha1(name.encode("utf-8")).hexdigest()[:10]

        return f'lithops-worker-{version.replace(".", "")}-{name_hash}'

    def _get_default_runtime_image_name(self):
        """
        Generates the default runtime image name
        """
        return utils.get_default_container_name(
            self.name, self.kn_config, 'lithops-knative-default'
        )

    def _get_service_host(self, service_name):
        """
        gets the service host needed for the invocation
        """
        logger.debug(f'Getting service host for: {service_name}')
        try:
            svc = self.custom_api.get_namespaced_custom_object(
                group=config.DEFAULT_GROUP,
                version=config.DEFAULT_VERSION,
                name=service_name,
                namespace=self.namespace,
                plural="services"
            )
            if svc is not None:
                service_host = svc['status']['url'][7:]
            else:
                raise Exception(f'Unable to get service details from {service_name}')
        except Exception as e:
            if json.loads(e.body)['code'] == 404:
                raise Exception(f'Knative service: resource "{service_name}" Not Found')
            else:
                raise (e)

        logger.debug(f'Service host: {service_host}')
        return service_host

    def _create_account_resources(self):
        """
        Creates the secret to access to the docker hub and the ServiceAcount
        """
        logger.debug("Creating Tekton account resources: Secret and ServiceAccount")
        string_data = {'username': self.kn_config['docker_user'],
                       'password': self.kn_config['docker_password']}
        secret_res = yaml.safe_load(config.secret_res)
        secret_res['stringData'] = string_data

        secret_res['metadata']['annotations']['tekton.dev/docker-0'] = "docker.io"

        account_res = yaml.safe_load(config.account_res)
        secret_res_name = secret_res['metadata']['name']
        account_res_name = account_res['metadata']['name']

        try:
            self.core_api.delete_namespaced_secret(secret_res_name, self.namespace)
        except Exception:
            # account resource Not Found - Not deleted
            pass

        try:
            self.core_api.delete_namespaced_service_account(account_res_name, self.namespace)
        except Exception:
            # account resource Not Found - Not deleted
            pass

        self.core_api.create_namespaced_secret(self.namespace, secret_res)
        self.core_api.create_namespaced_service_account(self.namespace, account_res)

    def _create_build_resources(self):
        logger.debug("Creating Tekton build resources: PipelineResource and Task")
        git_res = yaml.safe_load(config.git_res)
        git_res_name = git_res['metadata']['name']

        task_def = yaml.safe_load(config.task_def)
        task_name = task_def['metadata']['name']

        git_url_param = {'name': 'url', 'value': self.kn_config['git_url']}
        git_rev_param = {'name': 'revision', 'value': self.kn_config['git_rev']}
        params = [git_url_param, git_rev_param]
        git_res['spec']['params'] = params

        logger.debug(f'Setting git url to: {self.kn_config["git_url"]}')
        logger.debug(f'Setting git rev to: {self.kn_config["git_rev"]}')

        try:
            self.custom_api.delete_namespaced_custom_object(
                group="tekton.dev",
                version="v1alpha1",
                name=task_name,
                namespace=self.namespace,
                plural="tasks",
                body=client.V1DeleteOptions()
            )
        except Exception:
            # ksvc resource Not Found  - Not deleted
            pass

        try:
            self.custom_api.delete_namespaced_custom_object(
                group="tekton.dev",
                version="v1alpha1",
                name=git_res_name,
                namespace=self.namespace,
                plural="pipelineresources",
                body=client.V1DeleteOptions()
            )
        except Exception:
            # ksvc resource Not Found - Not deleted
            pass

        self.custom_api.create_namespaced_custom_object(
            group="tekton.dev",
            version="v1alpha1",
            namespace=self.namespace,
            plural="pipelineresources",
            body=git_res
        )

        self.custom_api.create_namespaced_custom_object(
            group="tekton.dev",
            version="v1alpha1",
            namespace=self.namespace,
            plural="tasks",
            body=task_def
        )

    def _build_default_runtime_from_git(self, runtime_name):
        """
        Builds the default runtime and pushes it to the docker container registry
        """
        if runtime_name.count('/') > 1:
            # container registry is in the provided runtime name
            cr, rn = runtime_name.split('/', 1)
        else:
            cr = 'docker.io'
            rn = runtime_name

        image_name, revision = rn.split(':')

        if cr == 'docker.io' and revision != 'latest':
            resp = requests.get('https://index.docker.io/v1/repositories/{}/tags/{}'
                                .format(runtime_name, revision))
            if resp.status_code == 200:
                logger.debug('Docker image docker.io/{}:{} already exists in Dockerhub. '
                             'Skipping build process.'.format(runtime_name, revision))
                return

        logger.info("Building default Lithops runtime from git with Tekton")

        if not all(key in self.kn_config for key in ["docker_user", "docker_password"]):
            raise Exception("You must provide 'docker_user' and 'docker_password'"
                            " to build the default runtime")

        task_run = yaml.safe_load(config.task_run)
        task_run['spec']['inputs']['params'] = []
        python_version = utils.CURRENT_PY_VERSION.replace('.', '')
        path_to_dockerfile = {'name': 'pathToDockerFile',
                              'value': 'lithops/compute/backends/knative/tekton/Dockerfile.python{}'.format(python_version)}
        task_run['spec']['inputs']['params'].append(path_to_dockerfile)
        image_url = {'name': 'imageUrl',
                     'value': '/'.join([cr, image_name])}
        task_run['spec']['inputs']['params'].append(image_url)
        image_tag = {'name': 'imageTag',
                     'value': revision}
        task_run['spec']['inputs']['params'].append(image_tag)

        self._create_account_resources()
        self._create_build_resources()

        task_run_name = task_run['metadata']['name']
        try:
            self.custom_api.delete_namespaced_custom_object(
                group="tekton.dev",
                version="v1alpha1",
                name=task_run_name,
                namespace=self.namespace,
                plural="taskruns",
                body=client.V1DeleteOptions()
            )
        except Exception:
            pass

        self.custom_api.create_namespaced_custom_object(
            group="tekton.dev",
            version="v1alpha1",
            namespace=self.namespace,
            plural="taskruns",
            body=task_run
        )

        logger.debug("Building runtime")
        pod_name = None
        w = watch.Watch()
        for event in w.stream(self.custom_api.list_namespaced_custom_object, namespace=self.namespace,
                              group="tekton.dev", version="v1alpha1", plural="taskruns",
                              field_selector="metadata.name={0}".format(task_run_name)):
            if event['object'].get('status'):
                pod_name = event['object']['status']['podName']
                w.stop()

        if pod_name is None:
            raise Exception('Unable to get the pod name from the task that is building the runtime')

        w = watch.Watch()
        for event in w.stream(self.core_api.list_namespaced_pod, namespace=self.namespace,
                              field_selector=f"metadata.name={pod_name}"):
            if event['object'].status.phase == "Succeeded":
                w.stop()
            if event['object'].status.phase == "Failed":
                w.stop()
                logger.debug('Something went wrong building the default Lithops runtime with Tekton')
                for container in event['object'].status.container_statuses:
                    if container.state.terminated.reason == 'Error':
                        logs = self.core_api.read_namespaced_pod_log(
                            name=pod_name,
                            container=container.name,
                            namespace=self.namespace
                        )
                        logger.debug("Tekton container '{}' failed: {}".format(container.name, logs.strip()))

                raise Exception('Unable to build the default Lithops runtime with Tekton')

        self.custom_api.delete_namespaced_custom_object(
            group="tekton.dev",
            version="v1alpha1",
            name=task_run_name,
            namespace=self.namespace,
            plural="taskruns",
            body=client.V1DeleteOptions()
        )

        logger.debug('Default Lithops runtime built from git and uploaded to Dockerhub')

    def _build_default_runtime(self, default_runtime_img_name):
        """
        Builds the default runtime
        """
        # Build default runtime using local dokcer
        dockerfile = "Dockefile.default-kn-runtime"
        with open(dockerfile, 'w') as f:
            f.write(f"FROM python:{utils.CURRENT_PY_VERSION}-slim-buster\n")
            f.write(config.DEFAULT_DOCKERFILE)
        try:
            self.build_runtime(default_runtime_img_name, dockerfile)
        finally:
            os.remove(dockerfile)

        # self._build_default_runtime_from_git(default_runtime_img_name)

    def _create_container_registry_secret(self):
        """
        Create the container registry secret in the cluster
        (only if credentials are present in config)
        """
        if not all(key in self.kn_config for key in ["docker_user", "docker_password"]):
            return

        logger.debug('Creating container registry secret')
        docker_server = self.kn_config['docker_server']
        docker_user = self.kn_config['docker_user']
        docker_password = self.kn_config['docker_password']

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

    def _create_service(self, runtime_name, runtime_memory, timeout):
        """
        Creates a service in knative based on the runtime_name and the memory provided
        """
        logger.debug("Creating Lithops runtime service in Knative")
        svc_res = yaml.safe_load(config.service_res)

        service_name = self._format_service_name(runtime_name, runtime_memory)
        svc_res['metadata']['name'] = service_name
        svc_res['metadata']['namespace'] = self.namespace

        logger.debug(f"Service name: {service_name}")
        logger.debug(f"Namespace: {self.namespace}")

        svc_res['spec']['template']['spec']['timeoutSeconds'] = timeout
        svc_res['spec']['template']['spec']['containerConcurrency'] = 1
        svc_res['spec']['template']['metadata']['labels']['lithops-version'] = __version__.replace('.', '-')
        svc_res['spec']['template']['metadata']['annotations']['autoscaling.knative.dev/maxScale'] = str(self.kn_config['max_workers'])

        container = svc_res['spec']['template']['spec']['containers'][0]
        container['image'] = runtime_name
        container['env'][0] = {'name': 'CONCURRENCY', 'value': '1'}
        container['env'][1] = {'name': 'TIMEOUT', 'value': str(timeout)}
        container['resources']['limits']['memory'] = f'{runtime_memory}Mi'
        container['resources']['limits']['cpu'] = str(self.kn_config['runtime_cpu'])
        container['resources']['requests']['memory'] = f'{runtime_memory}Mi'
        container['resources']['requests']['cpu'] = str(self.kn_config['runtime_cpu'])

        if not all(key in self.kn_config for key in ["docker_user", "docker_password"]):
            del svc_res['spec']['template']['spec']['imagePullSecrets']

        try:
            # delete the service resource if exists
            self.custom_api.delete_namespaced_custom_object(
                group=config.DEFAULT_GROUP,
                version=config.DEFAULT_VERSION,
                name=service_name,
                namespace=self.namespace,
                plural="services",
                body=client.V1DeleteOptions()
            )
            time.sleep(2)
        except Exception:
            pass

        # create the service resource
        self.custom_api.create_namespaced_custom_object(
            group=config.DEFAULT_GROUP,
            version=config.DEFAULT_VERSION,
            namespace=self.namespace,
            plural="services",
            body=svc_res
        )

        w = watch.Watch()
        for event in w.stream(self.custom_api.list_namespaced_custom_object,
                              namespace=self.namespace, group=config.DEFAULT_GROUP,
                              version=config.DEFAULT_VERSION, plural="services",
                              field_selector=f"metadata.name={service_name}",
                              timeout_seconds=300):
            if event['object'].get('status'):
                service_url = event['object']['status'].get('url')
                conditions = event['object']['status']['conditions']
                if conditions[0]['status'] == 'True' and \
                   conditions[1]['status'] == 'True' and \
                   conditions[2]['status'] == 'True':
                    w.stop()
                    time.sleep(2)

        logger.debug(f'Runtime Service created - URL: {service_url}')

        self.service_host_suffix = service_url[7:].replace(service_name, '')
        # Store service host suffix in local cache
        serice_host_data = {}
        serice_host_data['service_host_suffix'] = self.service_host_suffix
        dump_yaml_config(self.serice_host_filename, serice_host_data)
        self.kn_config['service_host_suffix'] = self.service_host_suffix

        return service_url

    def _generate_runtime_meta(self, runtime_name, memory):
        """
        Extract installed Python modules from docker image
        """
        logger.info(f"Extracting metadata from: {runtime_name}")
        payload = {}

        payload['service_route'] = "/metadata"

        try:
            runtime_meta = self.invoke(runtime_name, memory, payload, return_result=True)
        except Exception as e:
            raise Exception(f"Unable to extract metadata from the runtime: {e}")

        if not runtime_meta or 'preinstalls' not in runtime_meta:
            raise Exception(f'Failed getting runtime metadata: {runtime_meta}')

        return runtime_meta

    def deploy_runtime(self, runtime_name, memory, timeout):
        """
        Deploys a new runtime into the knative default namespace from an already built Docker image.
        As knative does not have a default image already published in a docker registry, lithops
        has to build it in the docker hub account provided by the user. So when the runtime docker
        image name is not provided by the user in the config, lithops will build the default.
        """
        try:
            default_image_name = self._get_default_runtime_image_name()
        except Exception:
            default_image_name = None

        if runtime_name == default_image_name:
            self._build_default_runtime(runtime_name)

        logger.info(f"Deploying runtime: {runtime_name} - Memory: {memory} Timeout: {timeout}")
        self._create_container_registry_secret()
        self._create_service(runtime_name, memory, timeout)
        runtime_meta = self._generate_runtime_meta(runtime_name, memory)

        return runtime_meta

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
            utils.create_handler_zip(config.FH_ZIP_LOCATION, entry_point, 'lithopsproxy.py')
            utils.run_command(cmd)
        finally:
            os.remove(config.FH_ZIP_LOCATION)

        logger.debug(f'Pushing runtime {runtime_name} to container registry')
        if utils.is_podman(docker_path):
            cmd = f'{docker_path} push {runtime_name} --format docker --remove-signatures'
        else:
            cmd = f'{docker_path} push {runtime_name}'
        utils.run_command(cmd)

        logger.debug('Building done!')

    def delete_runtime(self, runtime_name, memory, version=__version__):
        service_name = self._format_service_name(runtime_name, memory, version)
        logger.info(f'Deleting runtime: {service_name}')
        try:
            self.custom_api.delete_namespaced_custom_object(
                group=config.DEFAULT_GROUP,
                version=config.DEFAULT_VERSION,
                name=service_name,
                namespace=self.namespace,
                plural="services",
                body=client.V1DeleteOptions()
            )
        except Exception:
            pass

    def clean(self):
        """
        Deletes all runtimes deployed in knative
        """
        runtimes = self.list_runtimes()
        for img_name, memory, version in runtimes:
            self.delete_runtime(img_name, memory, version)

    def list_runtimes(self, runtime_name='all'):
        """
        List all the runtimes deployed in knative
        return: list of tuples [runtime_name, memory, version]
        """
        knative_services = self.custom_api.list_namespaced_custom_object(
            group=config.DEFAULT_GROUP,
            version=config.DEFAULT_VERSION,
            namespace=self.namespace,
            plural="services"
        )
        runtimes = []

        for service in knative_services['items']:
            try:
                template = service['spec']['template']
                labels = template['metadata']['labels']
                if labels and 'type' in labels and labels['type'] == 'lithops-runtime':
                    version = labels['lithops-version'].replace('-', '.')
                    container = template['spec']['containers'][0]
                    memory = container['resources']['requests']['memory'].replace('Mi', '')
                    memory = int(memory.replace('Gi', '')) * 1024 if 'Gi' in memory else memory
                    if runtime_name in container['image'] or runtime_name == 'all':
                        runtimes.append((container['image'], memory, version))
            except Exception:
                # It is not a lithops runtime
                pass

        return runtimes

    def invoke(self, runtime_name, memory, payload, return_result=False):
        """
        Invoke -- return information about this invocation
        """
        service_name = self._format_service_name(runtime_name, memory)
        if self.service_host_suffix:
            service_host = service_name + self.service_host_suffix
        else:
            service_host = self._get_service_host(service_name)

        headers = {}

        if self.ingress_endpoint:
            headers['Host'] = service_host
            endpoint = self.ingress_endpoint
        else:
            endpoint = f'http://{service_host}'

        if 'codeengine' in endpoint:
            endpoint = endpoint.replace('http://', 'https://')

        exec_id = payload.get('executor_id')
        call_ids = payload.get('call_ids')
        job_id = payload.get('job_id')
        route = payload.get("service_route", '/')

        try:
            parsed_url = urlparse(endpoint)

            if endpoint.startswith('https'):
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(parsed_url.netloc, context=ctx)
            else:
                conn = http.client.HTTPConnection(parsed_url.netloc)

            if exec_id and job_id and call_ids:
                logger.debug('ExecutorID {} | JobID {} - Invoking function call {}'
                             .format(exec_id, job_id, ', '.join(call_ids)))
            elif exec_id and job_id:
                logger.debug('ExecutorID {} | JobID {} - Invoking function'
                             .format(exec_id, job_id))
            else:
                logger.debug('Invoking function')

            conn.request("POST", route, body=json.dumps(payload, default=str), headers=headers)

            resp = conn.getresponse()
            headers = dict(resp.getheaders())
            resp_status = resp.status
            resp_data = resp.read().decode("utf-8")
            conn.close()
        except Exception as e:
            raise e

        if resp_status in [200, 202]:
            data = json.loads(resp_data)
            if return_result:
                return data
            return data["activationId"]
        elif resp_status == 404:
            raise Exception("Lithops runtime is not deployed in your k8s cluster")
        else:
            logger.debug('ExecutorID {} | JobID {} - Function call {} failed ({}). Retrying request'
                         .format(exec_id, job_id, ', '.join(call_ids), resp_status))

    def get_runtime_key(self, runtime_name, runtime_memory, version=__version__):
        """
        Method that creates and returns the runtime key.
        Runtime keys are used to uniquely identify runtimes within the storage,
        in order to know which runtimes are installed and which not.
        """
        service_name = self._format_service_name(runtime_name, runtime_memory, version)
        cluster = self.cluster.replace('https://', '').replace('http://', '')
        runtime_key = os.path.join(self.name, version, cluster, self.namespace, service_name)

        return runtime_key

    def get_runtime_info(self):
        """
        Method that returns all the relevant information about the runtime set
        in config
        """
        if 'runtime' not in self.kn_config or self.kn_config['runtime'] == 'default':
            self.kn_config['runtime'] = self._get_default_runtime_image_name()

        runtime_info = {
            'runtime_name': self.kn_config['runtime'],
            'runtime_cpu': self.kn_config['runtime_cpu'],
            'runtime_memory': self.kn_config['runtime_memory'],
            'runtime_timeout': self.kn_config['runtime_timeout'],
            'max_workers': self.kn_config['max_workers'],
        }

        return runtime_info
