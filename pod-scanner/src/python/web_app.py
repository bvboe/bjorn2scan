def parse_comma_separated_string(input_string):
    #Converts a comma-separated string into a list of trimmed items.
    if not input_string:
        return []

    return [item.strip() for item in input_string.split(",")]

from logging_config import setup_logging
setup_logging()
from kubernetes import client, config, watch
from flask import Flask, request, jsonify
import os
import json
import subprocess
import ast
import threading
import logging
import requests

logger = logging.getLogger(__name__)
NODE_NAME=os.getenv("NODE_NAME")
NODE_IP=os.getenv("NODE_IP")
POD_NAME=os.getenv("POD_NAME")
POD_NAMESPACE=os.getenv("POD_NAMESPACE")
POD_IP=os.getenv("POD_IP")
POTENTIAL_DOCKER_SOCKET_LOCATIONS = os.getenv("POTENTIAL_DOCKER_SOCKET_LOCATIONS")
POTENTIAL_CONTAINERD_SNAPSHOT_LOCATIONS = os.getenv("POTENTIAL_CONTAINERD_SNAPSHOT_LOCATIONS")
AWS_TAGS_PREFIX = os.getenv("AWS_TAGS_PREFIX")
AWS_TAGS_INCLUDE_LIST = parse_comma_separated_string(os.getenv("AWS_TAGS_INCLUDE_LIST"))
AWS_TAGS_EXCLUDE_LIST = parse_comma_separated_string(os.getenv("AWS_TAGS_EXCLUDE_LIST"))
GCP_TAGS_PREFIX = os.getenv("GCP_TAGS_PREFIX")
GCP_TAGS_INCLUDE_LIST = parse_comma_separated_string(os.getenv("GCP_TAGS_INCLUDE_LIST"))
GCP_TAGS_EXCLUDE_LIST = parse_comma_separated_string(os.getenv("GCP_TAGS_EXCLUDE_LIST"))
HOST_CONFIGURATION = None
GET_SBOM_LOCK = threading.Lock()
GCP_METADATA_URL = "http://metadata.google.internal/computeMetadata/v1/instance/attributes/"
GCP_METADATA_HEADERS = {"Metadata-Flavor": "Google"}

logger.info(f"Starting app on node {NODE_NAME}")
logger.info(f"NODE_NAME {NODE_NAME}")
logger.info(f"NODE_IP {NODE_IP}")
logger.info(f"POD_NAME {POD_NAME}")
logger.info(f"POD_NAMESPACE {POD_NAMESPACE}")
logger.info(f"POD_IP {POD_IP}")
logger.info(f"POTENTIAL_DOCKER_SOCKET_LOCATIONS {POTENTIAL_DOCKER_SOCKET_LOCATIONS}")
logger.info(f"POTENTIAL_CONTAINERD_SNAPSHOT_LOCATIONS {POTENTIAL_CONTAINERD_SNAPSHOT_LOCATIONS}")

def get_container_runtime():
    logger.debug("get_container_runtime()")
    config.load_incluster_config()
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

HOST_CONFIGURATION = get_host_configuration()
logger.info(f"Current host configuration: {HOST_CONFIGURATION}")

app = Flask(__name__)

def is_ready():
    if HOST_CONFIGURATION is None:
        return False
    else:
        return True

@app.route('/health')
def health_check():
    if is_ready():
        return jsonify({"status": "healthy"}), 200
    else:
        return jsonify({"status": "not ready"}), 400

@app.route("/hello")
def say_hello():
    status = None
    if is_ready():
        status = "ready"
    else:
        status = "not ready"

    result = {
        "status": status,
        "node_name": NODE_NAME,
        "pod_ip": POD_IP,
        "uptime": get_system_uptime()
    }
    strresult=json.dumps(result)
    logger.info(f"sayHello(): {strresult}")
    return strresult


def is_running_on_gcp():
    logger.info(f"is_running_on_gcp()")
    """Check if the code is running on a GCP instance."""
    try:
        response = requests.get(GCP_METADATA_URL, headers=GCP_METADATA_HEADERS, timeout=2)
        logger.info(f"is_running_on_gcp() - True")
        return True
    except requests.RequestException:
        logger.info(f"is_running_on_gcp() - False")
        return False

@app.route("/nodetags")
def get_node_tags():
    logger.info(f"get_node_tags()")
    result = {
        "host_name": NODE_NAME,
        "host_ip": NODE_IP
    }
    result.update(load_cloud_tags(get_aws_tags, AWS_TAGS_PREFIX, AWS_TAGS_INCLUDE_LIST, AWS_TAGS_EXCLUDE_LIST))
    result.update(load_cloud_tags(get_gcp_tags, GCP_TAGS_PREFIX, GCP_TAGS_INCLUDE_LIST, GCP_TAGS_EXCLUDE_LIST))
    logger.debug(f"get_node_tags() - {result}")
    return result

def get_aws_tags():
    """
    Retrieves instance identity document from AWS metadata service using IMDSv2.
    If not running on AWS, or if an error occurs, it returns an empty dictionary.
    """
    logger.info("get_aws_tags()")

    AWS_METADATA_TOKEN_URL = "http://169.254.169.254/latest/api/token"
    AWS_METADATA_DOCUMENT_URL = "http://169.254.169.254/latest/dynamic/instance-identity/document"
    TOKEN_TTL_SECONDS = "21600"
    HEADERS = {"X-aws-ec2-metadata-token-ttl-seconds": TOKEN_TTL_SECONDS}

    try:
        # Step 1: Get IMDSv2 token
        token_response = requests.put(AWS_METADATA_TOKEN_URL, headers=HEADERS, timeout=2)
        token_response.raise_for_status()
        token = token_response.text

        # Step 2: Use the token to get instance identity document
        headers_with_token = {"X-aws-ec2-metadata-token": token}
        instance_response = requests.get(AWS_METADATA_DOCUMENT_URL, headers=headers_with_token, timeout=2)
        instance_response.raise_for_status()

        # Step 3: Convert JSON response to a dictionary
        return instance_response.json()
    except requests.RequestException as e:
        logger.info("get_aws_tags() - not running on AWS, returning")
        #logger.warning(f"Failed to retrieve AWS metadata: {e}")
        return {}
    
def get_gcp_tags():
    logger.info(f"get_gcp_tags()")
    """
    Retrieves all instance attributes from GCP metadata server.
    For each attribute, fetches its corresponding value and returns them as a dictionary.

    If not running on GCP, it returns an empty dictionary.
    """
    if not is_running_on_gcp():
        logger.warning("Not running on GCP. Returning empty attribute map.")
        return {}

    try:
        # Get list of all attribute keys
        response = requests.get(GCP_METADATA_URL, headers=GCP_METADATA_HEADERS, timeout=30)
        response.raise_for_status()
        response_text = response.text
        logger.debug(f"get_gcp_tags() - Response text: \"{response_text}\"")
        attribute_keys = response_text.split("\n")

        attributes = {}
        for key in attribute_keys:
            key = key.strip()  # Remove unnecessary spaces

            # Skip empty or invalid keys
            if not key:
                logger.debug("get_gcp_tags() - Skipping empty attribute key")
                continue
            logger.debug(f"get_gcp_tags() - Load attribute for key: \"{key}\"")

            attr_url = f"{GCP_METADATA_URL}{key}"
            attr_response = requests.get(attr_url, headers=GCP_METADATA_HEADERS, timeout=30)
            attr_response.raise_for_status()
            attributes[key] = attr_response.text  # Store attribute value

        return attributes

    except requests.RequestException as e:
        logger.error(f"Error retrieving GCP instance attributes: {e}")
        return {}
        
def load_cloud_tags(retrieve_tag_function, tag_prefix, include_tag_list, exclude_tag_list):
    # First load all tags
    tags = retrieve_tag_function()

    # Step 1: Filter to include only specified tags (if include_tag_list is not empty)
    if include_tag_list:
        tags = {k: v for k, v in tags.items() if k in include_tag_list}

    # Step 2: Remove excluded tags
    tags = {k: v for k, v in tags.items() if k not in exclude_tag_list}

    # Step 3: Add tag_prefix to all keys
    tags = {f"{tag_prefix}{k}": v for k, v in tags.items()}

    return tags

@app.route("/")
def index():
    logger.info("index()")
    return "Scanner application running!\n"

@app.route("/image-sbom" , methods=['GET'])
def get_image_sbom():
    image = request.args.get('image')
    image_id = request.args.get('image_id')
    container_id = request.args.get('container_id')
    sbom_file = "/tmp/sbom.json"
    logger.info(f"get_image_sbom()")
    logger.info(f"image: {image}")
    logger.info(f"image_id: {image_id}")
    logger.info(f"container_id: {container_id}")
    if "@" in image:
        image_sha = image
    else:
        image_sha = image.split(":")[0] + "@" + image_id
    logger.debug(f"image_sha: {image_sha}")

    # This function is currently designed to only handle one call at the time
    # which is also the way the vulnerability coordinator works
    # The lock is just a safety feature
    with GET_SBOM_LOCK:
        if HOST_CONFIGURATION['runtime'] == "docker":
            logger.debug("Do Docker based scan")
            docker_host = HOST_CONFIGURATION['DOCKER_HOST']
            create_sbom(["./docker-sbom.sh", docker_host, sbom_file, image_sha])
            sbom = load_sbom(sbom_file)
            if sbom:
                return {"result": "success", "sbom": sbom}
            else:
                return {"result": "fail"}
        elif HOST_CONFIGURATION['runtime'] == "containerd":
            logger.debug("Do Containerd based scan")
            containerd_snapshot_folder = HOST_CONFIGURATION['CONTAINERD_SNAPSHOT_LOCATION']
            create_sbom(["./containerd-filesystem-sbom.sh", container_id, image, containerd_snapshot_folder, sbom_file])
            sbom = load_sbom(sbom_file)
            if sbom:
                return {"result": "success", "sbom": sbom}
            else:
                return {"result": "fail"}
        else:
            logger.error(f"Invalid configuration - {HOST_CONFIGURATION}, returning none")
            return {"result": "fail"}

@app.route("/host-sbom" , methods=['GET'])
def get_host_sbom():
    sbom_file = "/tmp/host-sbom.json"
    logger.info(f"get_host_sbom()")

    # This function is currently designed to only handle one call at the time
    # which is also the way the vulnerability coordinator works
    # The lock is just a safety feature
    with GET_SBOM_LOCK:
        create_sbom(["./host-sbom.sh", sbom_file])
        sbom = load_sbom(sbom_file)
        if sbom:
            return {"result": "success", "sbom": sbom}
        else:
            return {"result": "fail"}

def load_sbom(file_path):
    logger.info(f"load_sbom({file_path})")
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        # Handle the error if the file doesn't exist
        logger.error(f"The file {file_path} does not exist.")
        return None


def create_sbom(sbom_call):
    logger.info(f"create_sbom({sbom_call})")

    try:
        result = subprocess.run(sbom_call, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True)
        logger.debug(result.stdout)
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with return code {e.returncode}")
        logger.error(f"Command output:\n{e.output}")
        logger.error(f"Command error:\n{e.stderr}")
    except FileNotFoundError:
        logger.error("The specified command was not found.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")

def get_system_uptime():
    logger.info(f"get_system_uptime()")

    with open('/host/proc/uptime', 'r') as f:
        uptime_seconds = float(f.readline().split()[0])
    return uptime_seconds

