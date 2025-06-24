import logging
import os
import json
import subprocess
from kubernetes import client, config, watch
from kubernetes.client import Configuration

logger = logging.getLogger(__name__)

NODE_NAME=os.getenv("NODE_NAME")
NODE_IP=os.getenv("NODE_IP")
POTENTIAL_DOCKER_SOCKET_LOCATIONS = os.getenv("POTENTIAL_DOCKER_SOCKET_LOCATIONS")
POTENTIAL_CONTAINERD_SNAPSHOT_LOCATIONS = os.getenv("POTENTIAL_CONTAINERD_SNAPSHOT_LOCATIONS")
K8S_VERIFY_SSL = os.getenv("K8S_VERIFY_SSL", "true").lower() in ("1", "true", "yes")
logger.info(f"POTENTIAL_DOCKER_SOCKET_LOCATIONS {POTENTIAL_DOCKER_SOCKET_LOCATIONS}")
logger.info(f"POTENTIAL_CONTAINERD_SNAPSHOT_LOCATIONS {POTENTIAL_CONTAINERD_SNAPSHOT_LOCATIONS}")
logger.info(f"K8S_VERIFY_SSL {K8S_VERIFY_SSL}")

def get_container_runtime():
    logger.debug("get_container_runtime()")
    config.load_incluster_config()

    if K8S_VERIFY_SSL == False:
        # Get the default Kubernetes configuration and disable SSL verification, to maintain compatibility with certain Kubernetes distributions, like MicroK8s
        cfg = Configuration.get_default_copy()
        cfg.verify_ssl = False
        Configuration.set_default(cfg)

    v1 = client.CoreV1Api()
    nodes = v1.list_node()

    for node in nodes.items:
        node_name = node.metadata.name
        if node_name == NODE_NAME:
            logger.debug(f"Found {node.status.node_info.container_runtime_version}")
            return node.status.node_info.container_runtime_version
    
    return None

def get_host_configuration():
    logger.debug("get_host_configuration()")
    container_runtime = get_container_runtime()
    config_file_location = "/tmp/scanner-configuration.json"
    console_out = None

    if container_runtime.startswith("containerd"):
        logger.debug("Loading ContainerD runtime configuration")
        console_out = subprocess.run(["./containerd-check-environment.sh", config_file_location, POTENTIAL_CONTAINERD_SNAPSHOT_LOCATIONS], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True)
    elif container_runtime.startswith("docker"):
        logger.debug("Loading Docker runtime configuration")
        console_out = subprocess.run(["./docker-check-environment.sh", config_file_location, POTENTIAL_DOCKER_SOCKET_LOCATIONS], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True)
    else:
        logger.error(f"ERROR - Unknown runtime {container_runtime}")
        return None

    logger.debug(console_out.stdout)

    with open(config_file_location, 'r') as file:
        scanner_configuration = file.read()
        logger.debug(scanner_configuration)
        return json.loads(scanner_configuration)
