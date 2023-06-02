import os

# PufferBlow-api info
PACKAGE_NAME = "PufferBlow-api"
VERSION      = "0.1.0"
AUTHER       = "ramsy"
GITHUB       = "https://github.com/PufferBlow/PufferBlow-api"  

# PufferBlow-api default config file
PUFFERBLOW_CONFIG_PATH = f"{os.environ['HOME']}/.config/pufferblow-api/config.yaml"
PUFFERBLOW_CONFIG = f"""# This is the config file for pufferblow-api
# please if you do edit this file you will need
# to restart, in order to apply the changes

api:
 - host: "0.0.0.0"
 - port: 7575
 - logs_path: {os.environ['HOME']}/pufferblow_api.log
 - workers: 7 # number of workers for guvicorn
 - connection_timeout: 60 # in seconds

cassandra:
 - host: "0.0.0.0"
 - port: 9042{os.environ['HOME']}
 - username: <your username>
 - password: <your password>
"""
