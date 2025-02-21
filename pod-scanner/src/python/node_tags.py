def parse_comma_separated_string(input_string):
    #Converts a comma-separated string into a list of trimmed items.
    if not input_string:
        return []

    return [item.strip() for item in input_string.split(",")]

import logging
import requests
import os
logger = logging.getLogger(__name__)

AWS_TAGS_PREFIX = os.getenv("AWS_TAGS_PREFIX")
AWS_TAGS_INCLUDE_LIST = parse_comma_separated_string(os.getenv("AWS_TAGS_INCLUDE_LIST"))
AWS_TAGS_EXCLUDE_LIST = parse_comma_separated_string(os.getenv("AWS_TAGS_EXCLUDE_LIST"))
GCP_TAGS_PREFIX = os.getenv("GCP_TAGS_PREFIX")
GCP_TAGS_INCLUDE_LIST = parse_comma_separated_string(os.getenv("GCP_TAGS_INCLUDE_LIST"))
GCP_TAGS_EXCLUDE_LIST = parse_comma_separated_string(os.getenv("GCP_TAGS_EXCLUDE_LIST"))
GCP_METADATA_URL = "http://metadata.google.internal/computeMetadata/v1/instance/attributes/"
GCP_METADATA_HEADERS = {"Metadata-Flavor": "Google"}
NODE_NAME=os.getenv("NODE_NAME")
NODE_IP=os.getenv("NODE_IP")

def get_tags():
    logger.info(f"get_tags()")
    result = {
        "host_name": NODE_NAME,
        "host_ip": NODE_IP
    }
    result.update(load_cloud_tags(get_aws_tags, AWS_TAGS_PREFIX, AWS_TAGS_INCLUDE_LIST, AWS_TAGS_EXCLUDE_LIST))
    result.update(load_cloud_tags(get_gcp_tags, GCP_TAGS_PREFIX, GCP_TAGS_INCLUDE_LIST, GCP_TAGS_EXCLUDE_LIST))
    logger.debug(f"get_tags() - {result}")
    return result

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
