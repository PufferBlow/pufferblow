import os

from ruamel.yaml import YAML

from pufferblow_api import constants

yaml = YAML()

def load_config() -> dict:
    """ Returns the config file content in the form of a dict """
    if os.path.exists(constants.PUFFERBLOW_CONFIG_PATH) != True:
        os.mkdir(constants.PUFFERBLOW_CONFIG_PATH.replace("/config.yaml", ""))
        with open(constants.PUFFERBLOW_CONFIG_PATH, "w") as pufferblow_config_file:
            pufferblow_config_file.write(constants.PUFFERBLOW_CONFIG)
    
    with open(constants.PUFFERBLOW_CONFIG_PATH, "r") as config_file_content:
        config_file_content = yaml.safe_load(config_file_content)

    return config_file_content
