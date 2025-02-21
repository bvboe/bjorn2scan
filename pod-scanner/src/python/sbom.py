import logging
import subprocess
from host_configuration import get_host_configuration

logger = logging.getLogger(__name__)

HOST_CONFIGURATION = get_host_configuration()
logger.info(f"Current host configuration: {HOST_CONFIGURATION}")

def load_image_sbom(image, image_id, container_id):
    sbom_file = "/tmp/sbom.json"
    size_file = "/tmp/size.txt"
    logger.info(f"load_image_sbom()")
    logger.info(f"image: {image}")
    logger.info(f"image_id: {image_id}")
    logger.info(f"container_id: {container_id}")
    if "@" in image:
        image_sha = image
    else:
        image_sha = image.split(":")[0] + "@" + image_id
    logger.debug(f"image_sha: {image_sha}")

    if HOST_CONFIGURATION['runtime'] == "docker":
        logger.debug("Do Docker based scan")
        docker_host = HOST_CONFIGURATION['DOCKER_HOST']
        create_sbom(["./docker-sbom.sh", docker_host, sbom_file, image_sha])
        sbom = load_file(sbom_file)
        if sbom:
            return {"result": "success", "sbom": sbom}
        else:
            return {"result": "fail"}
    elif HOST_CONFIGURATION['runtime'] == "containerd":
        logger.debug("Do Containerd based scan")
        containerd_snapshot_folder = HOST_CONFIGURATION['CONTAINERD_SNAPSHOT_LOCATION']
        create_sbom(["./containerd-filesystem-sbom.sh", container_id, image, containerd_snapshot_folder, sbom_file, size_file])
        sbom = load_file(sbom_file)
        kb_size = load_file(size_file)
        if sbom:
            return {
                    "result": "success", 
                    "kb_size": kb_size,
                    "sbom": sbom
                    }
        else:
            return {"result": "fail"}
    else:
        logger.error(f"Invalid configuration - {HOST_CONFIGURATION}, returning none")
        return {"result": "fail"}

def load_host_sbom():
    sbom_file = "/tmp/host-sbom.json"
    logger.info(f"load_host_sbom()")

    create_sbom(["./host-sbom.sh", sbom_file])
    sbom = load_file(sbom_file)
    if sbom:
        return {"result": "success", "sbom": sbom}
    else:
        return {"result": "fail"}

def load_file(file_path):
    logger.info(f"load_file({file_path})")
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
