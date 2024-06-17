import json
from enum import Enum

from lithops.constants import (
    SA_INSTALL_DIR,
    SA_LOG_FILE,
    SA_CONFIG_FILE,
    SA_DATA_FILE,
    SA_TMP_DIR
)


class ExecMode(Enum):
    """
    Mode of execution
    """
    CONSUME = "consume"
    CREATE = "create"
    REUSE = "reuse"


MASTER_SERVICE_NAME = 'lithops-master.service'
MASTER_SERVICE_FILE = f"""
[Unit]
Description=Lithops Master Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 {SA_INSTALL_DIR}/master.py
Restart=always

[Install]
WantedBy=multi-user.target
"""

WORKER_SERVICE_NAME = 'lithops-worker.service'
WORKER_SERVICE_FILE = f"""
[Unit]
Description=Lithops Worker Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 {SA_INSTALL_DIR}/worker.py
Restart=always

[Install]
WantedBy=multi-user.target
"""

CLOUD_CONFIG_WORKER_PK = """
#cloud-config
users:
    - name: {0}
      ssh_authorized_keys:
        - {1}
      sudo: ALL=(ALL) NOPASSWD:ALL
      groups: sudo
      shell: /bin/bash
"""

CLOUD_CONFIG_WORKER = """
#cloud-config
bootcmd:
    - echo '{0}:{1}' | chpasswd
    - sed -i '/PasswordAuthentication no/c\PasswordAuthentication yes' /etc/ssh/sshd_config
    - echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
runcmd:
    - echo '{0}:{1}' | chpasswd
    - sed -i '/PasswordAuthentication no/c\PasswordAuthentication yes' /etc/ssh/sshd_config
    - echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
    - systemctl restart sshd
"""


def get_host_setup_script(docker=True):
    """
    Returns the script necessary for installing a lithops VM host
    """

    return """
    wait_internet_connection(){{
    echo "--> Checking internet connection"
    while ! (ping -c 1 -W 1 8.8.8.8| grep -q 'statistics'); do
    echo "Waiting for 8.8.8.8 - network interface might be down..."
    sleep 1
    done;
    }}

    install_packages(){{
    export DOCKER_REQUIRED={2};
    command -v docker >/dev/null 2>&1 || {{ export INSTALL_DOCKER=true; export INSTALL_LITHOPS_DEPS=true;}};
    command -v unzip >/dev/null 2>&1 || {{ export INSTALL_LITHOPS_DEPS=true; }};
    command -v pip3 >/dev/null 2>&1 || {{ export INSTALL_LITHOPS_DEPS=true; }};

    if [ "$INSTALL_DOCKER" = true ] && [ "$DOCKER_REQUIRED" = true ]; then
    wait_internet_connection;
    echo "--> Installing Docker"
    apt-get update;
    apt-get install apt-transport-https ca-certificates curl software-properties-common gnupg-agent -y;
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -;
    add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable";
    fi;

    if [ "$INSTALL_LITHOPS_DEPS" = true ]; then
    wait_internet_connection;
    echo "--> Installing Lithops system dependencies"
    apt-get update;

    if [ "$INSTALL_DOCKER" = true ] && [ "$DOCKER_REQUIRED" = true ]; then
    apt-get install unzip python3-pip docker-ce docker-ce-cli containerd.io -y --fix-missing;
    else
    apt-get install unzip python3-pip -y --fix-missing;
    fi;

    fi;

    if [[ ! $(pip3 list|grep "lithops") ]]; then
    wait_internet_connection;
    echo "--> Installing Lithops python dependencies"
    pip3 install -U flask gevent lithops boto3;
    fi;
    }}
    install_packages >> {1} 2>&1

    unzip -o /tmp/lithops_standalone.zip -d {0} > /dev/null 2>&1;
    rm /tmp/lithops_standalone.zip
    """.format(SA_INSTALL_DIR, SA_LOG_FILE, str(docker).lower())

def docker_login(config):
    if all(k in config for k in ("docker_server", "docker_user", "docker_password")):
        return f"""docker login -u {config['docker_user']} -p {config['docker_password']} {config['docker_server']} >> /tmp/kuku 2>&1
    """
    return ""

def get_master_setup_script(config, vm_data):
    """
    Returns master VM installation script
    """
    script = f"""#!/bin/bash
    rm -R {SA_INSTALL_DIR};
    mkdir -p {SA_INSTALL_DIR};
    mkdir -p {SA_TMP_DIR};

    setup_host(){{
    cp /tmp/lithops_standalone.zip {SA_INSTALL_DIR};
    echo '{json.dumps(vm_data)}' > {SA_DATA_FILE};
    echo '{json.dumps(config)}' > {SA_CONFIG_FILE};
    }}
    setup_host >> {SA_LOG_FILE} 2>&1;
    """
    script += get_host_setup_script()

    script += docker_login(config)
    script += f"""
    setup_service(){{
    echo '{MASTER_SERVICE_FILE}' > /etc/systemd/system/{MASTER_SERVICE_NAME};
    chmod 644 /etc/systemd/system/{MASTER_SERVICE_NAME};
    systemctl daemon-reload;
    systemctl stop {MASTER_SERVICE_NAME};
    systemctl enable {MASTER_SERVICE_NAME};
    systemctl start {MASTER_SERVICE_NAME};
    }}
    setup_service >> {SA_LOG_FILE} 2>&1;

    USER_HOME=$(eval echo ~${{SUDO_USER}});

    generate_ssh_key(){{
    echo '    StrictHostKeyChecking no
    UserKnownHostsFile=/dev/null' >> /etc/ssh/ssh_config;
    ssh-keygen -f $USER_HOME/.ssh/id_rsa -t rsa -N '';
    chown ${{SUDO_USER}}:${{SUDO_USER}} $USER_HOME/.ssh/id_rsa*;
    cp $USER_HOME/.ssh/* /root/.ssh;
    echo '127.0.0.1 lithops-master' >> /etc/hosts;
    }}
    test -f $USER_HOME/.ssh/id_rsa || generate_ssh_key >> {SA_LOG_FILE} 2>&1;
    """

    return script

def get_worker_setup_script(config, vm_data):
    """
    Returns worker VM installation script
    this script is expected to be executed only from Master VM
    """
    ssh_user = vm_data['ssh_credentials']['username']
    home_dir = '/root' if ssh_user == 'root' else f'/home/{ssh_user}'
    try:
        master_pub_key = open(f'{home_dir}/.ssh/id_rsa.pub', 'r').read()
    except Exception:
        master_pub_key = ''

    script = f"""#!/bin/bash
    rm -R {SA_INSTALL_DIR};
    mkdir -p {SA_INSTALL_DIR};
    mkdir -p {SA_TMP_DIR};
    """
    script += get_host_setup_script()

    script += docker_login(config)
    script += f"""
    echo '{json.dumps(config)}' > {SA_CONFIG_FILE};
    echo '{json.dumps(vm_data)}' > {SA_DATA_FILE};

    setup_service(){{
    systemctl stop {MASTER_SERVICE_NAME};
    echo '{WORKER_SERVICE_FILE}' > /etc/systemd/system/{WORKER_SERVICE_NAME};
    chmod 644 /etc/systemd/system/{WORKER_SERVICE_NAME};
    systemctl daemon-reload;
    systemctl stop {WORKER_SERVICE_NAME};
    systemctl enable {WORKER_SERVICE_NAME};
    systemctl start {WORKER_SERVICE_NAME};
    }}
    setup_service >> {SA_LOG_FILE} 2>&1
    USER_HOME=$(eval echo ~${{SUDO_USER}});
    echo '{master_pub_key}' >> $USER_HOME/.ssh/authorized_keys;
    echo '{vm_data['master_ip']} lithops-master' >> /etc/hosts
    """

    return script
