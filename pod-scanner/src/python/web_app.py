from logging_config import setup_logging
setup_logging()
from flask import Flask, request, jsonify
from node_tags import get_tags
from host_configuration import get_host_configuration
import os
import json
import subprocess
import threading
import logging
from sbom import load_host_sbom, load_image_sbom

logger = logging.getLogger(__name__)
NODE_NAME=os.getenv("NODE_NAME")
NODE_IP=os.getenv("NODE_IP")
POD_NAME=os.getenv("POD_NAME")
POD_NAMESPACE=os.getenv("POD_NAMESPACE")
POD_IP=os.getenv("POD_IP")
HOST_CONFIGURATION = None
GET_SBOM_LOCK = threading.Lock()

logger.info(f"Starting app on node {NODE_NAME}")
logger.info(f"NODE_NAME {NODE_NAME}")
logger.info(f"NODE_IP {NODE_IP}")
logger.info(f"POD_NAME {POD_NAME}")
logger.info(f"POD_NAMESPACE {POD_NAMESPACE}")
logger.info(f"POD_IP {POD_IP}")

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

@app.route("/nodetags")
def get_node_tags():
    logger.info(f"get_node_tags()")
    return get_tags()

@app.route("/")
def index():
    logger.info("index()")
    return "Scanner application running!\n"

@app.route("/image-sbom" , methods=['GET'])
def get_image_sbom():
    image = request.args.get('image')
    image_id = request.args.get('image_id')
    container_id = request.args.get('container_id')

    logger.info(f"get_image_sbom()")
    logger.info(f"image: {image}")
    logger.info(f"image_id: {image_id}")
    logger.info(f"container_id: {container_id}")

    # This function is currently designed to only handle one call at the time
    # which is also the way the vulnerability coordinator works
    # The lock is just a safety feature
    with GET_SBOM_LOCK:
        return load_image_sbom(image, image_id, container_id)

@app.route("/host-sbom" , methods=['GET'])
def get_host_sbom():
    logger.info(f"get_host_sbom()")

    # This function is currently designed to only handle one call at the time
    # which is also the way the vulnerability coordinator works
    # The lock is just a safety feature
    with GET_SBOM_LOCK:
        return load_host_sbom()

def get_system_uptime():
    logger.info(f"get_system_uptime()")

    with open('/host/proc/uptime', 'r') as f:
        uptime_seconds = float(f.readline().split()[0])
    return uptime_seconds

