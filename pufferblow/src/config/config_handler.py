import os
import tomllib

class ConfigHandler(object):
    """ ConfigHandler class handles PufferBlow's API config """

    config_file_path            : str   =   f"{os.environ['HOME']}/.pufferblow/config.toml"
    is_config_present           : bool
    config                      : dict
    script_dir                  : str   =   os.path.dirname(__file__)
    default_config_file_path    : str   =   f"{script_dir}/config_sample.toml"

    def __init__(self) -> None:
        pass

    def check_config(self) -> bool:
        """
        Checks if the config is present or not.

        Args:
            None.
        
        Returns:
            bool: True if the config is present, otherwise False.
        """
        self.is_config_present = os.path.exists(self.config_file_path)

        return self.is_config_present

    def write_config(self, config: str) -> None:
        """
        Writes the config file to the config file path

        Args:
            config (str): The config in toml format.
        Returns:
            None.
        """
        with open(self.config_file_path, "w") as f:
            f.write(config)

    def load_config(self, config_file_path: str | None = None) -> dict:
        """
        Loads the config file 
        
        Args:
            None.
        
        Returns:
            dict: the config data.
        """
        if config_file_path is None:
            config_file_path = self.config_file_path
        
        with open(self.config_file_path, "rb") as config_file_content:
            self.config = tomllib.load(config_file_content)

        return self.config 

    def check_config_values(self) -> dict:
        """
        Checks the config's values.

        Args:
            None.
        
        Returns:
            dict: of errors the function finds those values.
        """
        raise NotImplementedError

    def is_default_config(self) -> bool:
        """
        Checks if the config values are the default ones.

        Args:
            None.
        
        Returns:
            bool: True if the config values are the default ones, otherwise False.
        """
        default_config = self.load_config(
            config_file_path=self.default_config_file_path
        
        )
        keys = [
            {
                "supabase": [
                    "supabase_url",
                    "supabase_key",
                    {
                        "postgresql":[
                            "database_name",
                            "username",
                            "password",
                            "host",
                            "port",
                        ]
                    }
                ]
            } 
        ]

        # Checks if the values of the keys in the default_config file are the same 
        # as the one in the config file that is located locally
        for key in keys:
            for element in key:
                for i in key[element]:
                    if isinstance(i, dict):
                        for x in i:
                            for _ in i[x]:
                                if default_config[element][x][_] == self.config[element][x][_]:
                                    return True
                        continue
                    if default_config[element][i] == self.config[element][i]:
                        return True
        
        return False

