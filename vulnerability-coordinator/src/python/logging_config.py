import logging
import logging.config
import yaml

def setup_logging():
    with open("logging_config.yaml", "r") as file:
        config = yaml.safe_load(file)
    logging.config.dictConfig(config)
